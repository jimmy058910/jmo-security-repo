"""`jmo history list` must have one rendering path a test can execute (#1011).

It had two, and the `tabulate` one was **unreachable for every user and every
developer**:

    $ .venv/Scripts/python.exe -c "import tabulate"
    ModuleNotFoundError: No module named 'tabulate'

`pyproject.toml`'s runtime dependencies are PyYAML, croniter, requests,
rapidfuzz and rich. `tabulate` is not among them -- the only reference anywhere
was `types-tabulate`, a *type stub*, in the dev group. So `from tabulate import
tabulate` inside a `try` always raised, and the `except ImportError` fallback
was the live path on every normal install.

Three consequences, and the second is what makes this more than tidiness:

1. The aligned table never rendered. Users got one unaligned line per scan.
2. The unreachable branch drifted silently. It was the only place rendering
   `Duration (s)`, so #981's write-side fix would have been invisible without
   also touching the fallback -- and **no test could have caught that**, because
   no test can exercise a branch whose import always fails.
3. mypy type-checked a branch that cannot run, which is what `types-tabulate`
   in the dev group was for, and it made the dead branch look maintained.

Rendered with `rich` instead of adding `tabulate` to the runtime dependencies:
`rich` is already a runtime dependency and already renders tables elsewhere in
this CLI (`diff_commands.py`). One path, no new dependency, and no `types-*`
stub for a module the product does not depend on.
"""

from __future__ import annotations

import ast
import json
import tomllib
from pathlib import Path

import pytest

from scripts.cli.jmo import build_parser

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def populated_db(tmp_path: Path) -> Path:
    """A history database with one scan, built through the real schema."""
    from scripts.core.history_db import init_database, store_scan

    db = tmp_path / "history.db"
    init_database(db)

    results = tmp_path / "results"
    (results / "summaries").mkdir(parents=True)
    (results / "summaries" / "findings.json").write_text(
        json.dumps(
            [
                {
                    "id": "f1",
                    "tool": "semgrep",
                    "rule_id": "r1",
                    "severity": "HIGH",
                    "title": "t",
                    "description": "d",
                    "location": {"path": "a.py", "line": 1},
                }
            ]
        ),
        encoding="utf-8",
    )
    store_scan(
        db_path=db,
        results_dir=results,
        profile="balanced",
        tools=["semgrep"],
        branch="main",
        duration_seconds=12.5,
    )
    return db


def _run_list(db: Path, capsys: pytest.CaptureFixture[str], *extra: str) -> str:
    from scripts.cli.history_commands import cmd_history_list

    args = build_parser().parse_args(["history", "list", "--db", str(db), *extra])
    rc = cmd_history_list(args)
    assert rc == 0, "history list failed"
    return capsys.readouterr().out


# ---------------------------------------------------------------------------
# The property: one path, and it renders the columns it claims.
# ---------------------------------------------------------------------------


def test_the_table_renders_the_duration(
    populated_db: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Duration was the column that exposed the dead branch.

    It existed only in the unreachable tabulate table, so populating
    `scans.duration_seconds` (#981) still showed a user nothing.
    """
    out = _run_list(populated_db, capsys)

    assert "12.5" in out, f"the duration never reached the output:\n{out}"


def test_the_table_renders_every_column_it_declares(
    populated_db: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A header the renderer prints must correspond to a value it prints."""
    out = _run_list(populated_db, capsys)

    for header in ("Branch", "Profile", "Findings", "Duration"):
        assert header in out, f"missing column {header!r} in:\n{out}"
    assert "main" in out
    assert "balanced" in out


def test_json_output_is_unaffected(
    populated_db: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The negative control for the renderer change.

    `--json` must stay machine-readable; a Rich console writing into stdout
    would corrupt it, which is the same trap `diff_commands.py` hit when its
    summary panel landed in the middle of `--format json` output.
    """
    out = _run_list(populated_db, capsys, "--json")

    payload = json.loads(out)
    assert isinstance(payload, list)
    assert payload[0]["profile"] == "balanced"


def test_the_empty_case_still_says_so(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """No scans is not an error, and must not render an empty table."""
    from scripts.core.history_db import init_database

    db = tmp_path / "empty.db"
    init_database(db)

    out = _run_list(db, capsys)

    assert "No scans found" in out


# ---------------------------------------------------------------------------
# The structural half: no second path, and no stub for an absent dependency.
# ---------------------------------------------------------------------------


def test_nothing_under_scripts_imports_tabulate() -> None:
    """The unreachable branch must be gone, not merely bypassed.

    Asserted by AST over the whole tree rather than by grep in one file: the
    measured scope was two import sites, both in `history_commands.py`, and a
    check naming that file would not notice a third appearing elsewhere.
    """
    offenders: list[str] = []
    for path in (REPO_ROOT / "scripts").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "tabulate":
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "tabulate":
                        offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")

    assert not offenders, (
        f"tabulate is imported at {offenders}, but it is not a runtime "
        f"dependency -- that branch cannot execute for any user"
    )


def test_no_type_stub_remains_for_a_module_the_product_does_not_depend_on() -> None:
    """`types-tabulate` type-checked a branch that could not run.

    That is what made the dead branch look maintained. Derived from
    pyproject.toml rather than hardcoded to tabulate, so the same mistake with
    a different module also fails here.
    """
    pyproject = tomllib.loads(
        (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )
    runtime = {
        _dist_name(spec) for spec in pyproject["project"].get("dependencies", [])
    }
    for extra in (pyproject["project"].get("optional-dependencies") or {}).values():
        runtime |= {_dist_name(spec) for spec in extra}

    dev = pyproject.get("dependency-groups", {}).get("dev", [])
    stubs = {
        _dist_name(spec)
        for spec in dev
        if isinstance(spec, str) and _dist_name(spec).startswith("types-")
    }

    orphans = sorted(
        stub for stub in stubs if stub[len("types-") :].lower() not in runtime
    )

    assert not orphans, (
        f"type stubs with no corresponding runtime dependency: {orphans}. "
        f"A stub for a module the product does not import type-checks a branch "
        f"that cannot execute."
    )


def _dist_name(spec: str) -> str:
    """The bare distribution name from a PEP 508 requirement string."""
    for sep in ("[", ">", "<", "=", "!", "~", ";", " "):
        spec = spec.split(sep, 1)[0]
    return spec.strip().lower()


def test_the_stub_extractor_found_something() -> None:
    """Meta-guard: an extractor that finds no stubs asserts nothing above."""
    pyproject = tomllib.loads(
        (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )
    dev = pyproject.get("dependency-groups", {}).get("dev", [])
    stubs = [s for s in dev if isinstance(s, str) and s.startswith("types-")]

    assert len(stubs) >= 2, f"stub extractor found only {stubs}"
    assert any("types-PyYAML".lower() in s.lower() for s in stubs)
