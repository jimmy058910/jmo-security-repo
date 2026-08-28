#!/usr/bin/env python3
"""Guard: performance budgets must be sourced, and must not grow single-sample.

Regression for #742.

Two separate defects, both about a number nobody can check.

## 1. Fourteen citations of a source that never existed

`tests/performance/__init__.py`, `test_benchmarks.py` and
`test_history_db_performance.py` all attributed their targets to CLAUDE.md --
"Performance Targets (from CLAUDE.md)", "Target: <500ms (from CLAUDE.md)", and
so on. **CLAUDE.md has never contained a performance section.** Measured::

    $ git log --oneline --all -S "Performance Targets" -- CLAUDE.md
    $ git log --oneline --all -S "Diff (1000 findings)" -- CLAUDE.md

Both empty: no commit has ever added one. The issue named a single instance
("test_benchmark_3 cited a <200ms target from CLAUDE.md while asserting <100");
measuring the class found fourteen -- and the fourteenth only turned up when
this guard ran, because it is spelled "(CLAUDE.md target)" rather than "from
CLAUDE.md" and a grep for the first wording never found it.

The numbers are not wrong -- they are the repository's own targets, and
`tests/performance/__init__.py` is where they are declared. The citation was
what made them look externally sourced, and an unsourceable citation is worse
than no citation, because it stops the reader looking further.

This guard asserts the attribution from both ends: no test may credit CLAUDE.md
with a performance target, **and** CLAUDE.md must still contain none. If someone
adds a performance section to CLAUDE.md, the second test fails and this comment
is what they will read.

## 2. A budget measured once

53 tests (61 by the definition below) read a clock once and compare the result
to a fixed threshold. That is the shape #733 flaked on and #736 fixed: one
measurement on a shared runner. A median over N measures the code; one sample
measures the runner's mood.

Measured headroom from #742, by forcing each budget to 0 and reading the elapsed
value out of the failure message::

    2.3x  test_prioritization_performance.py::test_bulk_api_latency         CONVERTED
    2.7x  test_benchmarks.py::test_benchmark_3_trend_analysis_50_scans       CONVERTED
    3.8x  test_history_db_performance.py::test_upsert_findings_batch_performance    CONVERTED
    4.4x  test_benchmarks.py::test_benchmark_1_sqlite_scan_insert_100_findings      CONVERTED
    5.3x  test_history_db_performance.py::test_batch_insert_findings_optimized_performance  CONVERTED
    ...   14 others between 10x and 689x

#733 broke at 1.6x over budget. Under ~3x is a flake waiting for a busy runner;
3-6x is worth hardening; beyond that the budget is doing its job.

**Every test in that band is now converted** -- the whole table above, not only
the 3-6x rows. Each needed a different fresh precondition, which is why they
could not be done as one change: a fresh CACHE DIRECTORY for the EPSS bulk
fetch, nothing at all for the read-only trend analysis, and a fresh DATABASE
for the three that write rows. What remains in the inventory is the >6x
population, where the budget is doing its job.

So this stays a **ratchet**: it pins what exists per file so the population
cannot grow, and a conversion lowers it.

`median_seconds` (`tests/conftest.py`) is the conversion target, and a converted
test drops out of this inventory automatically -- it calls the helper rather
than a clock, so the detector below stops seeing it. Reducing a count therefore
fails until the entry is updated, which is what keeps the inventory honest.

**The helper is only honest for operations that can be repeated.** #742 measured
two ways it is not: `get_scores_bulk` consults a cache before calling the API
(fresh cache per sample 7.19s against a shared cache 1.55s), and anything whose
measured region writes to a database cannot be repeated in place at all. Check
the measured region for statefulness before converting; a conversion that
silently changes which code path is measured is worse than the flake.
"""

from __future__ import annotations

import ast
import importlib.util
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DOC_CHECKER = REPO_ROOT / "scripts" / "dev" / "check_doc_links.py"

_CLOCK_READS = {"perf_counter", "monotonic", "time", "process_time"}

# file -> number of tests that read a clock directly and assert against a
# numeric literal. Measured 2026-08-28. A test converted to `median_seconds`
# leaves this inventory on its own, so these only go down.
# 48, down from the 61 first recorded here. TWO separate movements, and they
# must not be conflated:
#
#   -12  the detector was over-matching. It asked "does a clock appear" and
#        counted `int(time.time())` used as a TIMESTAMP COLUMN VALUE. Three
#        files leave the inventory entirely on that correction
#        (test_scan_session, test_attestation_provenance,
#        test_history_db_future_integrations) and test_history_db.py drops
#        6 -> 1. Nothing about those tests changed.
#    -3  three budgets were genuinely CONVERTED to a median over fresh
#        databases -- the whole 3-6x headroom band from the table above:
#        test_upsert_findings_batch_performance (two regions),
#        test_batch_insert_findings_optimized_performance, and
#        test_benchmark_1_sqlite_scan_insert_100_findings.
#
# The second is what the ratchet exists to record. The first is a measurement
# of the instrument, and it mattered: the over-match made the conversion
# INVISIBLE, because the scan-row INSERT beside each timing site still called
# `time.time()`. A count that cannot fall cannot ratchet.
SINGLE_SAMPLE_BUDGETS: dict[str, int] = {
    "tests/cli/test_wizard_edge_cases.py": 2,
    "tests/edge_cases/test_diff_edge_cases.py": 1,
    "tests/performance/test_benchmarks.py": 3,
    "tests/performance/test_history_db_perf.py": 4,
    "tests/performance/test_load.py": 5,
    "tests/performance/test_prioritization_performance.py": 6,
    "tests/performance/test_stress.py": 4,
    "tests/unit/test_attestation_cicd.py": 1,
    "tests/unit/test_dedup_enhanced.py": 3,
    "tests/unit/test_diff_engine.py": 2,
    "tests/unit/test_history_db.py": 1,
    "tests/unit/test_history_db_performance.py": 9,
    "tests/unit/test_normalize_and_report_more.py": 1,
    "tests/unit/test_plugin_loader.py": 1,
    "tests/unit/test_tool_runner.py": 4,
    "tests/unit/test_trend_analyzer.py": 1,
}


def _tracked_test_modules() -> list[str]:
    spec = importlib.util.spec_from_file_location("check_doc_links", str(DOC_CHECKER))
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return sorted(
        p for p in mod.tracked_paths() if p.startswith("tests/") and p.endswith(".py")
    )


def _is_clock_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _CLOCK_READS
    )


def _measures_a_duration(fn: ast.AST) -> bool:
    """Does this function SUBTRACT two clock reads, rather than just read one?

    Requiring a subtraction, not a read, is a correction to the first version
    of this guard (#742). That one asked only "does a clock appear", which
    cannot tell ``elapsed = time.time() - start`` from ``int(time.time())``
    used as a **timestamp column value** -- and the history-db tests do the
    latter constantly, because every scan row needs one.

    Measured: the loose rule counted **61** tests, of which **49** time
    anything. The 12 others stamp a value and happen to assert some number,
    which any test may do. Worse, the over-match made a real conversion
    INVISIBLE: converting the two upsert budgets to `median_seconds_with_setup`
    removed both timing sites and the count did not move, because the scan-row
    INSERT beside them still called `time.time()`. A ratchet that cannot see a
    conversion cannot be lowered by one, which is the whole mechanism.

    Both operand shapes are accepted -- a clock call inside the subtraction,
    and a name bound from one (``start = perf_counter() ... end - start``).
    The second finds nothing in the corpus today; it is here because its
    absence is a property of this codebase rather than of the rule.
    """
    clock_names = {
        target.id
        for node in ast.walk(fn)
        if isinstance(node, ast.Assign) and _is_clock_call(node.value)
        for target in node.targets
        if isinstance(target, ast.Name)
    }
    for sub in ast.walk(fn):
        if not (isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.Sub)):
            continue
        if any(_is_clock_call(c) for c in ast.walk(sub)):
            return True
        if any(isinstance(c, ast.Name) and c.id in clock_names for c in ast.walk(sub)):
            return True
    return False


def _single_sample_budget_tests(source: str) -> list[str]:
    """Tests that time an operation once and assert against a numeric literal.

    A test converted to ``median_seconds`` calls the helper instead of
    subtracting clocks, so it does not match -- which is why converting one
    reduces the count here rather than needing a second list of exemptions.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:  # pragma: no cover - would fail collection first
        return []
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not node.name.startswith("test_"):
            continue
        if not _measures_a_duration(node):
            continue
        asserts_number = any(
            isinstance(stmt, ast.Assert)
            and any(
                isinstance(c, ast.Constant) and isinstance(c.value, (int, float))
                for c in ast.walk(stmt.test)
            )
            for stmt in ast.walk(node)
        )
        if asserts_number:
            found.append(node.name)
    return found


def _survey() -> dict[str, int]:
    counts: dict[str, int] = {}
    for rel in _tracked_test_modules():
        hits = _single_sample_budget_tests(
            (REPO_ROOT / rel).read_text(encoding="utf-8", errors="replace")
        )
        if hits:
            counts[rel] = len(hits)
    return counts


def test_single_sample_budgets_do_not_spread() -> None:
    """Regression for #742: a wall-clock budget measured once."""
    counts = _survey()
    assert sum(counts.values()) > 0, "the detector found nothing; it has gone inert"

    new = {rel: n for rel, n in counts.items() if rel not in SINGLE_SAMPLE_BUDGETS}
    assert not new, (
        "a new test asserts a wall-clock budget from a single sample (#742). "
        "One measurement on a shared runner measures the runner's mood; use "
        "`median_seconds` from tests/conftest.py, and read its docstring first "
        "if the measured region writes to a database or populates a cache:\n"
        + "\n".join(f"  {rel}: {n}" for rel, n in sorted(new.items()))
    )

    grew = {
        rel: (SINGLE_SAMPLE_BUDGETS[rel], counts.get(rel, 0))
        for rel in SINGLE_SAMPLE_BUDGETS
        if counts.get(rel, 0) > SINGLE_SAMPLE_BUDGETS[rel]
    }
    assert not grew, f"a recorded file gained single-sample budgets: {grew}"

    shrank = {
        rel: (SINGLE_SAMPLE_BUDGETS[rel], counts.get(rel, 0))
        for rel in SINGLE_SAMPLE_BUDGETS
        if counts.get(rel, 0) < SINGLE_SAMPLE_BUDGETS[rel]
    }
    assert not shrank, (
        "a file has fewer single-sample budgets than recorded, which is good -- "
        "update SINGLE_SAMPLE_BUDGETS so the ratchet holds at the new level:\n"
        + "\n".join(
            f"  {rel}: recorded {was}, measured {now}"
            for rel, (was, now) in sorted(shrank.items())
        )
    )


# CLAUDE.md near a budget or the word "target" -- an *attribution*, not a
# mention. Matching the bare filename flagged five legitimate lines
# (test_cli_helpers on the config table, test_docker_tag_pattern_drift on
# dev-only, test_version_consistency on release archaeology), and would have made
# the guard hostile to any test that discusses CLAUDE.md at all.
_ATTRIBUTION = re.compile(
    r"CLAUDE\.md[^\n]{0,40}(?:<\s*\d+\s*(?:ms|s|MB|GB)|target)"
    r"|(?:<\s*\d+\s*(?:ms|s|MB|GB)|target)[^\n]{0,40}CLAUDE\.md",
    re.IGNORECASE,
)
# The corrections themselves name CLAUDE.md in order to say it is not the source.
_DISCLAIMER = re.compile(r"\bnot in\b|\bnever\b|\bno performance\b", re.IGNORECASE)


def test_median_seconds_with_setup_keeps_the_setup_off_the_clock() -> None:
    """The separation the helper exists for, asserted directly.

    Every converted budget has enough headroom to absorb its own fixture cost,
    so folding the setup INTO the measurement leaves each of them green --
    verified by mutation, which is how this test came to exist. The budgets
    cannot police the helper; only the helper's own contract can.

    The margin is deliberately coarse: setup sleeps 20x longer than the
    operation, so a Windows `perf_counter` resolution of ~1 ms cannot explain
    the difference either way.
    """
    import time as _time

    from tests.conftest import median_seconds_with_setup

    setup_calls = 0

    def slow_setup() -> str:
        nonlocal setup_calls
        setup_calls += 1
        _time.sleep(0.05)
        return "state"

    def quick_operation(state: str) -> None:
        assert state == "state", "setup's return value must reach the operation"
        _time.sleep(0.0025)

    elapsed = median_seconds_with_setup(slow_setup, quick_operation, samples=3)

    assert setup_calls == 3, (
        f"setup ran {setup_calls} times for 3 samples; it must be rebuilt per "
        "sample or the second sample measures the first one's leftovers"
    )
    assert elapsed < 0.03, (
        f"median was {elapsed * 1000:.1f}ms for a 2.5ms operation behind a 50ms "
        "setup -- the setup is being timed, so the measurement reports the "
        "fixture rather than the code"
    )


def test_no_test_credits_claude_md_with_a_performance_target() -> None:
    """Regression for #742: fourteen citations of a section that never existed.

    This file is excluded from its own walk. It has to quote the citations it
    forbids in order to document them, and a source-scanning guard that matches
    its own literals is a known shape in this repository. Note when it appeared:
    the guard was green while the file was untracked and red the moment it was
    staged, because coverage comes from ``git ls-files``. Untracked-green is the
    mirror of the gitignored-red the #855 guard hit.
    """
    self_path = Path(__file__).relative_to(REPO_ROOT).as_posix()
    offenders: list[str] = []
    for rel in _tracked_test_modules():
        if rel == self_path:
            continue
        text = (REPO_ROOT / rel).read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _ATTRIBUTION.search(line) and not _DISCLAIMER.search(line):
                offenders.append(f"{rel}:{lineno}: {line.strip()[:90]}")

    assert not offenders, (
        "a test cites CLAUDE.md as the source of a performance target. It has "
        "never contained one; the targets are declared in "
        "tests/performance/__init__.py:\n" + "\n".join(offenders)
    )


def test_claude_md_still_declares_no_performance_targets() -> None:
    """The other end of the attribution (#742).

    If CLAUDE.md ever gains a performance section, crediting it stops being
    false -- and this test is what should fail first, so the change is a
    decision rather than a drift.
    """
    text = (REPO_ROOT / "CLAUDE.md").read_text(encoding="utf-8")
    lowered = text.lower()
    for phrase in ("performance target", "benchmark target", "critical path benchmark"):
        assert phrase not in lowered, (
            f"CLAUDE.md now contains {phrase!r}. The tests were corrected to stop "
            "citing it (#742); if it is now a real source, update them and this "
            "test together rather than leaving the two disagreeing."
        )
