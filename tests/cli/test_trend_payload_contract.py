"""The trend consumers must read keys the trend producer actually emits.

`jmo trends analyze` printed this, on a window where findings fell by 2540
(-90.6%, trend `"improving"`):

```text
[#] IMPROVEMENT METRICS
  -> Net Change: +0 findings (+0.0%) - STABLE
  [T] Resolved: 0
  + Introduced: 0
```

The correct numbers were in the payload the whole time. The renderer read
`improvement["net_change"]`, `["resolved"]`, `["introduced"]` and
`["percent_change"]` -- four keys `_compute_improvement_metrics` has never
emitted -- so every one fell back to its `.get()` default. Two more sites did
the same: `security_score["history"]` (really `historical_scores`), which meant
the score-change line never printed, and `metadata["scan_ids"]` (the IDs are in
`analysis["scans"]`), which left the CSV export's `Scan ID` column blank in
every file it has ever written. Three of seven Prometheus metrics were
structurally zero. See #918.

`net_change` is the *diff engine's* vocabulary -- `diff_commands.py:640` is the
only place in the repo that sets it -- so this is a renderer reading a
neighbouring subsystem's dictionary. Chunk 12 fixed the identical class in
`jmo diff` (`diff_commands.py:228-239`); the trend side was never checked.

A `.get(key, default)` against a key nobody emits cannot fail. It produces a
plausible, well-formed, wrong number, which is why 8,000 tests and a full
chunk-15 sweep both missed it: chunk 15's oracle checked *selection* (which
scans) and not *rendering* (which fields).

So this guard is structural rather than example-based. It AST-scans every
`x.get("literal", ...)` in the consumer modules, resolves `x` to the section of
the analysis dict it was bound from, and asserts the key exists in a payload
produced by a real `TrendAnalyzer` run.

**The extractor needs its own guard.** An earlier version seeded only
parameters named `analysis`, so it could not resolve reads inside helpers that
take a section directly -- `_format_improvement_metrics(improvement)` was
invisible to it, and it reported **zero** absent keys for the very file
containing the headline defect. A scan that silently finds nothing passes every
assertion built on it, so `test_extractor_actually_traces_reads` pins a floor
and names sites it must find.
"""

from __future__ import annotations

import ast
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

import pytest

from scripts.core.trend_analyzer import TrendAnalyzer

CONSUMERS = {
    "trend_exporters": Path("scripts/core/trend_exporters.py"),
    "trend_formatters": Path("scripts/cli/trend_formatters.py"),
}

#: Parameter name -> the analysis section it carries. Without this the scan
#: cannot follow a helper that is handed a section rather than the whole dict.
PARAM_SECTIONS = {
    "improvement": "improvement_metrics",
    "improvement_metrics": "improvement_metrics",
    "metadata": "metadata",
    "security_score": "security_score",
    "severity_trends": "severity_trends",
}

#: The scan traced 62 reads when this was written. A floor well under that
#: still fails loudly if the AST walk stops resolving receivers.
MIN_TRACED_READS = 45


def _make_db(path: Path, count: int = 6) -> None:
    """A small history database with findings, so every section is populated."""
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE scans (
            id TEXT PRIMARY KEY, timestamp INTEGER NOT NULL, timestamp_iso TEXT NOT NULL,
            branch TEXT, commit_hash TEXT, profile TEXT, tools TEXT,
            total_findings INTEGER DEFAULT 0, critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0, medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0, info_count INTEGER DEFAULT 0,
            duration_seconds REAL DEFAULT 0
        )
        """)
    conn.execute("""
        CREATE TABLE findings (
            scan_id TEXT, fingerprint TEXT, severity TEXT, tool TEXT, rule_id TEXT,
            path TEXT, start_line INTEGER, end_line INTEGER, message TEXT,
            raw_finding TEXT
        )
        """)
    now = int(time.time())
    for i in range(count):
        ts = now - (5 * 86400) + (i * 3600)
        # counts move, so improvement_metrics is not trivially zero
        conn.execute(
            "INSERT INTO scans (id, timestamp, timestamp_iso, branch, profile, tools,"
            " total_findings, critical_count, high_count, medium_count, low_count,"
            " info_count) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                f"scan-{i:04d}",
                ts,
                time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(ts)),
                None,
                "balanced",
                json.dumps(["semgrep"]),
                20 - i,
                3 - (i % 2),
                5,
                6,
                3,
                3 - (i % 2),
            ),
        )
        # One finding survives the whole window, one is unique to each scan,
        # and the FIRST scan carries three extra that never come back. The
        # asymmetry is deliberate: with resolved == introduced, swapping the
        # two counts is undetectable, and a mutation proved it.
        rows = [
            (
                f"scan-{i:04d}",
                "fp-stable",
                "HIGH",
                "semgrep",
                "r1",
                "a.py",
                1,
                1,
                "m",
                "{}",
            ),
            (
                f"scan-{i:04d}",
                f"fp-{i}",
                "MEDIUM",
                "semgrep",
                "r2",
                "b.py",
                1,
                1,
                "m",
                "{}",
            ),
        ]
        if i == 0:
            rows += [
                (
                    f"scan-{i:04d}",
                    f"fp-gone-{n}",
                    "LOW",
                    "semgrep",
                    "r3",
                    "c.py",
                    1,
                    1,
                    "m",
                    "{}",
                )
                for n in range(3)
            ]
        conn.executemany(
            "INSERT INTO findings (scan_id, fingerprint, severity, tool, rule_id, path,"
            " start_line, end_line, message, raw_finding) VALUES (?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
    conn.commit()
    conn.close()


@pytest.fixture(scope="module")
def payload(tmp_path_factory) -> dict[str, Any]:
    """A real analysis dict, from a real TrendAnalyzer run."""
    db = tmp_path_factory.mktemp("payload") / "history.db"
    _make_db(db)
    with TrendAnalyzer(db) as analyzer:
        return analyzer.analyze_trends()


def _traced_reads(
    source: Path, payload: dict[str, Any]
) -> list[tuple[str, str, int, bool]]:
    """Every `x.get("literal", ...)` whose receiver resolves into the payload.

    Returns (function, "recv['key']", lineno, key_exists).
    """
    tree = ast.parse(source.read_text(encoding="utf-8"))
    rows: list[tuple[str, str, int, bool]] = []
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        bind: dict[str, Any] = {}
        for arg in fn.args.args:
            if arg.arg == "analysis":
                bind[arg.arg] = payload
            elif arg.arg in PARAM_SECTIONS:
                bind[arg.arg] = payload.get(PARAM_SECTIONS[arg.arg])
        for node in ast.walk(fn):
            if not (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Attribute)
                and node.value.func.attr == "get"
                and isinstance(node.value.func.value, ast.Name)
                and node.value.args
                and isinstance(node.value.args[0], ast.Constant)
                and isinstance(node.value.args[0].value, str)
            ):
                continue
            recv = node.value.func.value.id
            key = node.value.args[0].value
            base = bind.get(recv)
            if not isinstance(base, dict):
                continue
            bind[node.targets[0].id] = base.get(key)
            rows.append((fn.name, f"{recv}[{key!r}]", node.lineno, key in base))
    return rows


@pytest.mark.parametrize("module", sorted(CONSUMERS))
def test_consumers_read_only_keys_the_producer_emits(
    module: str, payload: dict[str, Any]
) -> None:
    """No consumer may read a key absent from a real analysis payload."""
    source = CONSUMERS[module]
    absent = [
        f"{source.name}:{line}  {fn}()  {expr}"
        for fn, expr, line, present in _traced_reads(source, payload)
        if not present
    ]
    assert not absent, (
        f"{module} reads {len(absent)} key(s) the analyzer never emits; each one "
        "silently yields its .get() default:\n  " + "\n  ".join(absent)
    )


def test_extractor_actually_traces_reads(payload: dict[str, Any]) -> None:
    """Meta-guard: an extractor that finds nothing passes the test above.

    The first version of this scan resolved only `analysis`-named parameters and
    reported zero absent keys for `trend_formatters.py` -- the file holding the
    defect. Assert both a floor and specific sites it must reach.
    """
    all_rows = [
        (module, fn, expr)
        for module, source in CONSUMERS.items()
        for fn, expr, _line, _present in _traced_reads(source, payload)
    ]
    assert len(all_rows) >= MIN_TRACED_READS, (
        f"extractor traced only {len(all_rows)} reads (floor {MIN_TRACED_READS}); "
        "it has stopped resolving receivers"
    )

    # The helper that was invisible to the first version.
    assert any(
        fn == "_format_improvement_metrics" for _module, fn, _expr in all_rows
    ), "extractor no longer reaches helpers that take a section as a parameter"

    # And the four keys #918 was about are the ones that must stay resolvable.
    improvement_reads = {
        expr for _module, fn, expr in all_rows if fn == "_format_improvement_metrics"
    }
    for key in ("net_change", "resolved", "introduced", "percentage_change"):
        assert any(key in e for e in improvement_reads), (
            f"expected _format_improvement_metrics to read {key!r}; "
            f"traced: {sorted(improvement_reads)}"
        )


def test_improvement_metrics_carry_real_values(payload: dict[str, Any]) -> None:
    """The headline numbers must reflect the data, not a `.get()` default.

    The fixture's findings drop over the window, so a renderer reading the
    right keys sees non-zero values. Reading the wrong ones yields exactly 0 --
    which is what shipped.
    """
    im = payload["improvement_metrics"]
    for key in (
        "net_change",
        "resolved",
        "introduced",
        "percentage_change",
        "total_change",
    ):
        assert key in im, f"improvement_metrics is missing {key!r}"

    assert im["net_change"] == im["total_change"]
    assert (
        im["total_change"] != 0
    ), "fixture must produce a real change to be meaningful"
    assert im["resolved"] > 0, "findings present in the first scan and not the last"
    assert im["introduced"] > 0, "findings present in the last scan and not the first"
    assert (
        im["resolved"] != im["introduced"]
    ), "fixture must be asymmetric, or swapping the two counts is undetectable"

    # NOT asserted: resolved - introduced == -total_change. It looks like an
    # identity and is not one. `total_change` comes from the scans table's
    # `total_findings` column, while resolved/introduced are counted from
    # fingerprints in the findings table, and the two disagree whenever a scan
    # stored fewer finding rows than it counted -- which #848 makes possible.
    # Writing it as an assertion would either fail here or, worse, pass
    # vacuously.


def test_resolved_and_introduced_match_a_fingerprint_oracle(
    tmp_path: Path,
) -> None:
    """Counted from the findings, cross-checked against an independent query."""
    db = tmp_path / "history.db"
    _make_db(db, count=6)

    with TrendAnalyzer(db) as analyzer:
        result = analyzer.analyze_trends()
    im = result["improvement_metrics"]
    first, last = result["scans"][0]["id"], result["scans"][-1]["id"]

    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        f = {
            r[0]
            for r in conn.execute(
                "SELECT fingerprint FROM findings WHERE scan_id = ?", (first,)
            )
        }
        last_fps = {
            r[0]
            for r in conn.execute(
                "SELECT fingerprint FROM findings WHERE scan_id = ?", (last,)
            )
        }
    finally:
        conn.close()

    assert im["resolved"] == len(f - last_fps)
    assert im["introduced"] == len(last_fps - f)


def test_scan_ids_are_not_read_from_metadata(payload: dict[str, Any]) -> None:
    """The CSV export took scan IDs from `metadata["scan_ids"]`, which is empty.

    The IDs are in `analysis["scans"]`. This pins where they actually live, so a
    future edit cannot quietly point back at the metadata dict.
    """
    assert "scan_ids" not in payload["metadata"]
    assert payload["scans"], "fixture must produce scans"
    assert all(s.get("id") for s in payload["scans"])
