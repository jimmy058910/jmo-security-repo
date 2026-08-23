#!/usr/bin/env python3
"""Guard: no test module may import conftest by bare module name.

Regression guard for #968. `tests/core/test_error_recovery.py` did::

    from conftest import IS_WINDOWS, skip_on_windows

`IS_WINDOWS` and `skip_on_windows` live in the top-level `tests/conftest.py`,
but there is no `tests/__init__.py`, and pytest inserts each test file's own
directory onto `sys.path`. So the bare name `conftest` resolves to whichever
`conftest.py` module the interpreter bound first in `sys.modules` -- normally
`tests/conftest.py`, but under `-n 8` a worker that collects `tests/jmo_mcp/`
(which has its own local `conftest.py`) first binds the name to the wrong
module, and the import raises. That surfaces as a collection ERROR, not a
test failure, so a summary-only read or a `--maxfail`-truncated log misses
it entirely -- 21 tests silently dropped from the run.

The fix is `pyproject.toml`'s `pythonpath = ["."]`, which puts the repo root
on `sys.path` and lets `tests` resolve as a PEP-420 namespace package:
`from tests.conftest import ...` is then unambiguous regardless of worker
collection order. `tests/e2e/test_docker_workflows.py` already used this
qualified form before this guard existed.

This scans with `ast`, not text search, so a docstring or string literal that
merely *mentions* the banned import -- as this file's own docstring does, and
as the planted-violation tests below write into scratch files -- is never
mistaken for an actual import statement. That is also why this file needs no
exclusion to pass its own scan; `test_the_self_exclusion_carries_no_weight`
below proves it rather than assuming it.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS_DIR = REPO_ROOT / "tests"
THIS_FILE = Path(__file__).resolve()


def find_bare_conftest_imports(
    scan_dir: Path, *, exclude: Path | None = None
) -> list[str]:
    """Return 'path:line -> <statement>' for every bare `conftest` import.

    Catches both `import conftest` and `from conftest import ...`, at any
    nesting level (module scope, inside a function, inside a class or a
    try/except) -- `ast.walk` finds the statement wherever it sits, unlike
    an anchored `^from conftest import` grep, which would miss one written
    inside a function body.
    """
    violations: list[str] = []

    for path in sorted(scan_dir.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        if exclude is not None and path.resolve() == exclude:
            continue
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
        except (SyntaxError, UnicodeDecodeError):
            continue  # not a scanning concern here; nothing importable anyway

        try:
            rel = path.relative_to(REPO_ROOT).as_posix()
        except ValueError:
            # scan_dir is outside the repo (a tmp_path scratch tree in the
            # planted-violation tests below) -- report relative to the scan
            # root instead of failing the walk.
            rel = path.relative_to(scan_dir).as_posix()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "conftest":
                        violations.append(f"{rel}:{node.lineno} -> import conftest")
            elif isinstance(node, ast.ImportFrom):
                # level == 0 is a bare/absolute import ("conftest"). A
                # relative form (level > 0) already names its package
                # unambiguously and is not the bug this guards against --
                # moot here anyway since tests/ has no __init__.py.
                if node.module == "conftest" and node.level == 0:
                    names = ", ".join(alias.name for alias in node.names)
                    violations.append(
                        f"{rel}:{node.lineno} -> from conftest import {names}"
                    )

    return violations


def test_no_test_module_imports_conftest_by_bare_name():
    """Every conftest import under tests/ must be qualified as tests.conftest.

    Fails if any module resolves `conftest` by bare name -- pytest's
    per-directory sys.path insertion makes that ambiguous the moment more
    than one conftest.py exists anywhere under tests/, and which one wins
    depends on xdist worker collection order (#968).
    """
    violations = find_bare_conftest_imports(TESTS_DIR, exclude=THIS_FILE)
    assert not violations, (
        "these modules import 'conftest' by bare name, which resolves to "
        "whichever conftest.py a worker happened to import first under "
        "-n 8 (#968) -- use 'from tests.conftest import ...' instead:\n  "
        + "\n  ".join(violations)
    )


def test_guard_detects_a_planted_bare_import(tmp_path):
    """The guard must be able to fail.

    A guard that cannot fail is worse than no guard -- it is confidence
    without substance. This plants the exact statement #968 shipped, in a
    scratch file the real scan never sees, and confirms the scanner catches
    it.
    """
    scratch = tmp_path / "tests_scratch"
    scratch.mkdir()
    (scratch / "test_planted.py").write_text(
        "from conftest import IS_WINDOWS, skip_on_windows\n",
        encoding="utf-8",
    )

    violations = find_bare_conftest_imports(scratch)
    assert any("test_planted.py" in v for v in violations), (
        "guard failed to detect a planted bare 'from conftest import' -- "
        f"got: {violations}"
    )


def test_guard_detects_a_planted_indented_bare_import(tmp_path):
    """Catches the bug even when it is not at column 0.

    The measurement grep used while diagnosing #968 was anchored
    (`^from conftest import`) and would miss an import written inside a
    function body. AST has no such blind spot -- this proves it.
    """
    scratch = tmp_path / "tests_scratch_indented"
    scratch.mkdir()
    (scratch / "test_planted_indented.py").write_text(
        "def helper():\n"
        "    from conftest import IS_WINDOWS\n"
        "    return IS_WINDOWS\n",
        encoding="utf-8",
    )

    violations = find_bare_conftest_imports(scratch)
    assert any(
        "test_planted_indented.py" in v for v in violations
    ), f"guard failed to detect an indented bare import -- got: {violations}"


def test_guard_allows_the_qualified_form(tmp_path):
    """`from tests.conftest import ...` -- the actual fix -- must not be flagged.

    Without this, the guard could be "satisfied" by any rewrite that merely
    removes the word `conftest`, not specifically by adopting the qualified
    form the fix uses.
    """
    scratch = tmp_path / "tests_scratch_fixed"
    scratch.mkdir()
    (scratch / "test_fixed.py").write_text(
        "from tests.conftest import IS_WINDOWS, skip_on_windows\n",
        encoding="utf-8",
    )

    assert find_bare_conftest_imports(scratch) == []


def test_the_self_exclusion_carries_no_weight():
    """Prove `exclude=THIS_FILE` above is not what makes this file's scan pass.

    This repo has been bitten before by a source-scanning guard whose own
    literals matched its own scan, with an exclusion silently doing the work
    of hiding that. This scanner uses `ast`, so the string
    'from conftest import' appearing in this file's docstring, or written as
    scratch-file content by the tests above, is never mistaken for an
    import statement -- only a real `ast.Import`/`ast.ImportFrom` node
    counts. Scanning this file's own directory WITHOUT the exclusion must
    still attribute zero violations to this file; if it doesn't, the
    `exclude=` parameter on the real guard is masking an actual bug here,
    not working around a benign text collision.
    """
    violations = find_bare_conftest_imports(THIS_FILE.parent, exclude=None)
    this_file_prefix = THIS_FILE.relative_to(REPO_ROOT).as_posix() + ":"
    this_file_violations = [v for v in violations if v.startswith(this_file_prefix)]
    assert this_file_violations == [], (
        "this guard's own file was flagged even though it contains no real "
        "bare import -- the exclude= parameter on the main guard would be "
        f"masking a genuine bug, not a false positive: {this_file_violations}"
    )
