"""`jmo trends` must select the scans it says it selected.

Every defect chunk 15 found lives in the *selection* layer -- which rows a
subcommand chooses -- or in how the answer is framed. None was in the
statistics: `score` agreed with an independent SQL computation to the point
throughout. So this file asserts selection and framing, and leaves Mann-Kendall
to `test_trend_analyzer.py`.

Measured on the maintainer's 2214-scan history database before the fix:

* ``--branch`` defaulted to ``main``, which **0** of 2214 scans carry (1852 are
  NULL, 134 are ``dev``, across 29 distinct values). Six of the seven data
  subcommands returned "No scans found" on their default invocation (#781).
* ``--days 365`` and ``--days 3650`` returned byte-identical 1000-scan results,
  and reported the truncation point as the window's start date (#911).
* ``--last -5`` returned all 2214 scans, because SQLite defines a negative
  ``LIMIT`` as no limit (#914).
* ``--format json`` emitted an English sentence on the empty path -- which was
  the default path (#913).
* ``--branch`` was accepted and discarded by ``show``, ``compare`` and
  ``developers`` (#912).
* ``developers`` raised ``KeyError: 'scan_count'`` (#779), and behind it a
  second ``KeyError: 1`` from indexing dict rows as tuples -- so the command had
  never once run to completion.

`tests/cli/test_trend_commands.py` held 52 tests through all of it. Two
structural reasons, both avoided here (#916):

1. **Every one of its fixtures writes ``branch = "main"``**, the single value
   production never contains, so the broken default was the only default it
   exercised. The corpus below mirrors the real distribution instead: mostly
   NULL, some named branches, no ``main``.
2. **All 52 build a hand-written ``class Args``**, so no test could notice a
   flag argparse sets to ``None``, one argparse never creates, or one the
   command ignores. Everything here goes through ``_add_trends_args``.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import time
from pathlib import Path

import pytest

from scripts.cli.jmo import _add_trends_args
from scripts.cli.trend_commands import (
    _context_window,
    cmd_trends_analyze,
    cmd_trends_developers,
    cmd_trends_insights,
    cmd_trends_score,
)
from scripts.core.history_db import get_trend_summary, list_scans
from scripts.core.trend_analyzer import TrendAnalyzer, normalize_insight

# The real branch distribution, scaled down. `main` is deliberately absent: a
# fixture that contains it cannot reproduce the defect this file exists for.
BRANCH_MIX = [None] * 12 + ["dev"] * 5 + ["feature/x"] * 3


def _parser() -> argparse.ArgumentParser:
    """The real `jmo trends` parser, not a stand-in for it."""
    ap = argparse.ArgumentParser(prog="jmo")
    sub = ap.add_subparsers(dest="cmd")
    _add_trends_args(sub)
    return ap


def _parse(*argv: str) -> argparse.Namespace:
    return _parser().parse_args(["trends", *argv])


def _make_db(path: Path, branches: list[str | None], *, spread_days: int = 5) -> None:
    """Build a history database whose branch column mirrors production."""
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE scans (
            id TEXT PRIMARY KEY,
            timestamp INTEGER NOT NULL,
            timestamp_iso TEXT NOT NULL,
            branch TEXT,
            commit_hash TEXT,
            profile TEXT,
            tools TEXT,
            total_findings INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            info_count INTEGER DEFAULT 0,
            duration_seconds REAL DEFAULT 0
        )
        """)
    conn.execute("""
        CREATE TABLE findings (
            scan_id TEXT,
            fingerprint TEXT,
            severity TEXT,
            tool TEXT,
            rule_id TEXT,
            path TEXT,
            start_line INTEGER,
            end_line INTEGER,
            message TEXT,
            raw_finding TEXT
        )
        """)
    now = int(time.time())
    for i, branch in enumerate(branches):
        # Newest last, all comfortably inside a 30-day window.
        ts = now - (spread_days * 86400) + (i * 3600)
        conn.execute(
            "INSERT INTO scans (id, timestamp, timestamp_iso, branch, profile, tools,"
            " total_findings, critical_count, high_count, medium_count, low_count,"
            " info_count) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                f"scan-{i:04d}",
                ts,
                time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(ts)),
                branch,
                "balanced",
                json.dumps(["semgrep"]),
                10 - (i % 3),
                1,
                2,
                3,
                1,
                3 - (i % 3),
            ),
        )
    conn.commit()
    conn.close()


@pytest.fixture
def git_cwd(tmp_path: Path, monkeypatch) -> Path:
    """Run from inside something `developers` will accept as a repository.

    `cmd_trends_developers` falls back to ``Path.cwd()``; there is no
    ``--repo`` flag, whatever its docstring used to claim. Setting
    ``args.repo`` here would fabricate the very surface this file exists to
    catch, so the real fallback is what gets exercised.
    """
    (tmp_path / ".git").mkdir(exist_ok=True)
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def mixed_db(tmp_path: Path) -> Path:
    """A corpus shaped like production: mostly NULL branch, and no `main`."""
    db = tmp_path / "history.db"
    _make_db(db, BRANCH_MIX)
    return db


def _oracle(db: Path, sql: str, params: tuple = ()) -> int:
    """Count rows through a second, read-only connection.

    Read-only so a probe cannot alter what it is measuring, and a separate
    query so the expectation is not computed by the code under test.
    """
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        return conn.execute(sql, params).fetchone()[0]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# The default invocation -- #781
# ---------------------------------------------------------------------------


def test_branch_defaults_to_no_filter_in_the_parser() -> None:
    """`--branch` is opt-in. It used to default to the string "main"."""
    assert _parse("analyze").branch is None
    assert _parse("score").branch is None
    assert _parse("insights").branch is None
    assert _parse("regressions").branch is None
    assert _parse("developers").branch is None


def test_default_invocation_sees_every_branch(mixed_db: Path) -> None:
    """The default analyses all 20 scans, not the 0 that carry `main`.

    The oracle asserts the fixture really does contain no `main`, so a corpus
    that quietly grew one could not make this pass for the wrong reason.
    """
    assert _oracle(mixed_db, "SELECT COUNT(*) FROM scans WHERE branch = 'main'") == 0
    expected = _oracle(mixed_db, "SELECT COUNT(*) FROM scans")

    with TrendAnalyzer(mixed_db) as analyzer:
        result = analyzer.analyze_trends()

    assert result["metadata"].get("status") != "no_data"
    assert result["metadata"]["scan_count"] == expected == 20


def test_explicit_branch_still_narrows(mixed_db: Path) -> None:
    """Defaulting to everything must not break filtering to something."""
    expected = _oracle(mixed_db, "SELECT COUNT(*) FROM scans WHERE branch = 'dev'")

    with TrendAnalyzer(mixed_db) as analyzer:
        result = analyzer.analyze_trends(branch="dev")

    assert result["metadata"]["scan_count"] == expected == 5


def test_null_branch_scans_are_reachable_only_without_a_filter(
    mixed_db: Path,
) -> None:
    """A `branch = ?` comparison can never match NULL, whatever is passed.

    This is why the fix is "no filter" rather than "a better branch name":
    12 of the 20 scans are unreachable through any value of --branch.
    """
    nulls = _oracle(mixed_db, "SELECT COUNT(*) FROM scans WHERE branch IS NULL")
    assert nulls == 12

    with TrendAnalyzer(mixed_db) as analyzer:
        for candidate in ("main", "dev", "feature/x", "NULL", ""):
            narrowed = analyzer.analyze_trends(branch=candidate or None)
            if candidate:
                assert narrowed["metadata"].get("scan_count", 0) < nulls
        unfiltered = analyzer.analyze_trends()

    assert unfiltered["metadata"]["scan_count"] == 20


# ---------------------------------------------------------------------------
# The silent 1000-row cap -- #911
# ---------------------------------------------------------------------------


def test_window_is_not_capped_at_a_thousand_scans(tmp_path: Path) -> None:
    """`--days N` returns every scan in N days.

    A hardcoded ``limit=1000`` made ``--days 365`` and ``--days 3650`` return
    identical results on a 2214-scan database. 1200 rows is the smallest corpus
    that can tell a removed cap from a raised one.
    """
    db = tmp_path / "big.db"
    _make_db(db, [None] * 1200, spread_days=20)
    total = _oracle(db, "SELECT COUNT(*) FROM scans")
    assert total == 1200

    with TrendAnalyzer(db) as analyzer:
        wide = analyzer.analyze_trends(days=365)
        wider = analyzer.analyze_trends(days=3650)

    assert wide["metadata"]["scan_count"] == total
    assert wider["metadata"]["scan_count"] == total


def test_reported_date_range_starts_at_the_oldest_scan(tmp_path: Path) -> None:
    """The truncation point must not be reported as the window's start.

    Under the cap, `date_range.start` was the timestamp of the 1000th-newest
    scan -- a real date, plausibly formatted, and not the start of anything the
    user asked for.
    """
    db = tmp_path / "big.db"
    _make_db(db, [None] * 1200, spread_days=20)
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    oldest = conn.execute("SELECT MIN(timestamp_iso) FROM scans").fetchone()[0]
    conn.close()

    with TrendAnalyzer(db) as analyzer:
        result = analyzer.analyze_trends(days=365)

    assert result["metadata"]["date_range"]["start"] == oldest


def test_list_scans_accepts_no_limit_and_rejects_a_negative_one(
    mixed_db: Path,
) -> None:
    """SQLite reads a negative LIMIT as *no* limit; the boundary rejects it."""
    conn = sqlite3.connect(mixed_db)
    conn.row_factory = sqlite3.Row
    try:
        assert len(list_scans(conn, limit=None)) == 20
        assert len(list_scans(conn, limit=3)) == 3
        with pytest.raises(ValueError, match="limit must be >= 1"):
            list_scans(conn, limit=-5)
        with pytest.raises(ValueError, match="limit must be >= 1"):
            list_scans(conn, limit=0)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Degenerate numeric input -- #914
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("subcommand", "flag", "value"),
    [
        ("analyze", "--last", "-5"),
        ("analyze", "--last", "0"),
        ("analyze", "--days", "-5"),
        ("analyze", "--days", "0"),
        ("score", "--last", "0"),
        ("score", "--days", "-1"),
        ("insights", "--last", "-1"),
        ("regressions", "--last", "0"),
        ("developers", "--last", "0"),
        ("developers", "--top", "0"),
        ("show", "--context", "-1"),
    ],
)
def test_out_of_range_counts_are_rejected_by_the_parser(
    subcommand: str, flag: str, value: str
) -> None:
    """Rejected before the value can reach SQL.

    ``--last -5`` used to be the only way to ask for the whole table, and
    ``--last 0`` was indistinguishable from omitting the flag because
    `_get_scans` dispatched on truthiness.
    """
    argv = ["trends", subcommand, flag, value]
    if subcommand == "show":
        argv.append("scan-0001")
    with pytest.raises(SystemExit) as exc:
        _parser().parse_args(argv)
    assert exc.value.code == 2


def test_zero_is_rejected_by_the_analyzer_too(mixed_db: Path) -> None:
    """The analyzer is a public API, so it does not rely on the parser."""
    with TrendAnalyzer(mixed_db) as analyzer:
        with pytest.raises(ValueError, match="--last must be >= 1"):
            analyzer.analyze_trends(last_n=0)
        with pytest.raises(ValueError, match="--days must be >= 1"):
            analyzer.analyze_trends(days=-5)


# ---------------------------------------------------------------------------
# The empty result -- #913, and the exit code
# ---------------------------------------------------------------------------


def test_empty_json_is_still_json(mixed_db: Path, capsys) -> None:
    """A caller that asked for JSON gets JSON, empty or not.

    The `no_data` return sat above the format dispatch, so the machine-readable
    path emitted "No scans found for the specified criteria" -- on what was
    then the default invocation.
    """
    args = _parse(
        "analyze", "--branch", "nope", "--format", "json", "--db", str(mixed_db)
    )
    rc = cmd_trends_analyze(args)

    payload = json.loads(capsys.readouterr().out)
    assert payload["metadata"]["scan_count"] == 0
    assert payload["metadata"]["status"] == "no_data"
    assert rc == 0


@pytest.mark.parametrize(
    ("command", "subcommand"),
    [
        (cmd_trends_analyze, "analyze"),
        (cmd_trends_score, "score"),
        (cmd_trends_insights, "insights"),
    ],
)
def test_empty_result_is_not_an_error(command, subcommand: str, mixed_db: Path) -> None:
    """rc 0, matching `jmo history list` for the same empty query."""
    args = _parse(subcommand, "--branch", "nope", "--db", str(mixed_db))
    assert command(args) == 0


def test_empty_message_names_the_filters_that_excluded_everything(
    mixed_db: Path, capsys
) -> None:
    """ "No scans found" is unactionable when the user set none of the filters.

    The default invocation applied an implicit branch and an implicit window,
    then reported neither.
    """
    args = _parse("analyze", "--branch", "nope", "--days", "7", "--db", str(mixed_db))
    cmd_trends_analyze(args)

    out = capsys.readouterr().out
    assert "nope" in out
    assert "7 days" in out


# ---------------------------------------------------------------------------
# Flags the command must actually use -- #912
# ---------------------------------------------------------------------------


def test_show_and_compare_do_not_accept_a_branch_they_would_discard() -> None:
    """Both are addressed by scan ID; neither ever read `--branch`.

    Accepting a filter and ignoring it is worse than rejecting it: a user who
    passes one believes it took effect.
    """
    for argv in (
        ["trends", "show", "scan-0001", "--branch", "dev"],
        ["trends", "compare", "scan-0001", "scan-0002", "--branch", "dev"],
    ):
        with pytest.raises(SystemExit) as exc:
            _parser().parse_args(argv)
        assert exc.value.code == 2

    # ...and still work without it.
    assert _parse("show", "scan-0001").scan_id == "scan-0001"
    assert _parse("compare", "scan-0001", "scan-0002").scan_id_2 == "scan-0002"


def test_developers_honours_the_branch_it_advertises(
    mixed_db: Path, git_cwd: Path, capsys
) -> None:
    """It called `analyze_trends(last_n=...)` and took the signature default.

    So it filtered on `main` regardless of `--branch`, and could never return
    data on a database with no `main` scans -- not even with an explicit
    `--last`. The output must therefore differ between two real branches.
    """
    outputs = []
    for branch in ("dev", "feature/x"):
        args = _parse("developers", "--branch", branch, "--db", str(mixed_db))
        cmd_trends_developers(args)
        outputs.append(capsys.readouterr().out)

    assert outputs[0] != outputs[1]


def test_developers_survives_the_empty_path(
    tmp_path: Path, git_cwd: Path, capsys
) -> None:
    """The no-data path raised KeyError: 'scan_count' and printed a traceback.

    Every other subcommand checked `status` first; `developers` read the key
    unguarded, and the empty path was its default invocation.
    """
    db = tmp_path / "empty.db"
    _make_db(db, [])
    args = _parse("developers", "--db", str(db))

    rc = cmd_trends_developers(args)

    captured = capsys.readouterr()
    assert rc == 0
    assert "Traceback" not in captured.err
    assert "scan_count" not in captured.err


def test_developers_reads_findings_as_the_mapping_they_are(
    mixed_db: Path, git_cwd: Path, capsys
) -> None:
    """`get_findings_for_scan` returns list[dict]; the code indexed `f[1]`.

    That raised `KeyError: 1` on every real database, three lines below the
    `KeyError: 'scan_count'` that masked it -- so this command had never run to
    completion. It needs findings present to reach the failing line at all.
    """
    conn = sqlite3.connect(mixed_db)
    conn.executemany(
        "INSERT INTO findings (scan_id, fingerprint, severity, tool, rule_id, path,"
        " start_line, end_line, message, raw_finding) VALUES (?,?,?,?,?,?,?,?,?,?)",
        [
            (
                "scan-0000",
                "fp-resolved",
                "HIGH",
                "semgrep",
                "r1",
                "a.py",
                1,
                1,
                "m",
                "{}",
            ),
            ("scan-0019", "fp-kept", "HIGH", "semgrep", "r2", "b.py", 1, 1, "m", "{}"),
        ],
    )
    conn.commit()
    conn.close()

    args = _parse("developers", "--db", str(mixed_db))

    rc = cmd_trends_developers(args)

    assert rc == 0
    assert "KeyError" not in capsys.readouterr().err


def test_show_context_window_surrounds_the_target(mixed_db: Path) -> None:
    """The window is drawn around the target scan, not from a prefix.

    `cmd_trends_show` used to materialise `list_scans(..., limit=1000)` and
    search it for the target, so any scan outside the newest 1000 reported
    "Could not locate scan in timeline" -- about a row it had already
    loaded three lines earlier.
    """
    conn = sqlite3.connect(mixed_db)
    conn.row_factory = sqlite3.Row
    try:
        target = dict(
            conn.execute("SELECT * FROM scans WHERE id = ?", ("scan-0010",)).fetchone()
        )
        window = _context_window(conn, target, None, 3)
        ids = [s["id"] for s in window]
    finally:
        conn.close()

    # 3 before + target + 3 after, oldest first, target in the middle.
    assert ids == [f"scan-{i:04d}" for i in range(7, 14)]
    assert ids[3] == "scan-0010"


def test_show_context_window_clamps_at_the_ends(mixed_db: Path) -> None:
    """Fewer neighbours near either end, and never a duplicate target."""
    conn = sqlite3.connect(mixed_db)
    conn.row_factory = sqlite3.Row
    try:
        oldest = dict(
            conn.execute("SELECT * FROM scans WHERE id = ?", ("scan-0000",)).fetchone()
        )
        newest = dict(
            conn.execute("SELECT * FROM scans WHERE id = ?", ("scan-0019",)).fetchone()
        )
        first = [s["id"] for s in _context_window(conn, oldest, None, 3)]
        last = [s["id"] for s in _context_window(conn, newest, None, 3)]
    finally:
        conn.close()

    assert first == ["scan-0000", "scan-0001", "scan-0002", "scan-0003"]
    assert last == ["scan-0016", "scan-0017", "scan-0018", "scan-0019"]
    assert len(set(first)) == len(first)


def test_show_context_window_respects_an_explicit_branch(mixed_db: Path) -> None:
    """A target on a named branch draws its context from that branch."""
    conn = sqlite3.connect(mixed_db)
    conn.row_factory = sqlite3.Row
    try:
        target = dict(
            conn.execute(
                "SELECT * FROM scans WHERE branch = ? ORDER BY timestamp LIMIT 1",
                ("dev",),
            ).fetchone()
        )
        window = _context_window(conn, target, "dev", 5)
        branches = {s["branch"] for s in window}
    finally:
        conn.close()

    assert branches == {"dev"}


def test_developers_empty_message_names_the_filters(
    mixed_db: Path, git_cwd: Path, capsys
) -> None:
    """The no-data path must say what excluded everything.

    Distinct from the `scan_count < 2` path below it, which reports only a
    number. Both now return 0, so the exit code alone cannot tell them
    apart -- the message is what carries the information.
    """
    args = _parse("developers", "--branch", "nope", "--db", str(mixed_db))

    rc = cmd_trends_developers(args)

    out = capsys.readouterr().out
    assert rc == 0
    assert "nope" in out


# ---------------------------------------------------------------------------
# Metadata must describe the data, not echo the request -- #911's sibling
# ---------------------------------------------------------------------------


def test_scan_ids_report_the_branch_of_the_scans_not_of_the_flag(
    mixed_db: Path,
) -> None:
    """`--scan-ids` bypasses the branch filter, so echoing it back is a lie."""
    with TrendAnalyzer(mixed_db) as analyzer:
        result = analyzer.analyze_trends(
            branch="nope", scan_ids=["scan-0012", "scan-0013"]
        )

    assert result["metadata"]["scan_count"] == 2
    assert result["metadata"]["branch"] != "nope"


# ---------------------------------------------------------------------------
# `jmo history trends` shares the default and a different backend
# ---------------------------------------------------------------------------


def test_history_trends_backend_also_defaults_to_every_branch(
    mixed_db: Path,
) -> None:
    """`get_trend_summary` used a strict `branch = ?` with no falsy escape.

    It backs `jmo history trends`, which is the ninth entry point on this
    surface and carried the same `main` default.
    """
    conn = sqlite3.connect(mixed_db)
    conn.row_factory = sqlite3.Row
    try:
        every = get_trend_summary(conn, None, days=30)
        just_dev = get_trend_summary(conn, "dev", days=30)
        assert every is not None and every["scan_count"] == 20
        assert just_dev is not None and just_dev["scan_count"] == 5
        assert get_trend_summary(conn, "main", days=30) is None
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# The insights contract -- #910
# ---------------------------------------------------------------------------


def test_insights_are_strings_and_consumers_must_cope(mixed_db: Path) -> None:
    """`_generate_insights` is annotated `-> list[str]` and always was.

    Two consumers read `insight.get(...)`, so `--export-html` crashed on every
    invocation that reached it. The test fixture in
    `tests/unit/test_trend_exporters.py` declared seven-key dicts instead, which
    is what let the mismatch ship: a shape declared in a fixture is not the
    shape.
    """
    with TrendAnalyzer(mixed_db) as analyzer:
        result = analyzer.analyze_trends()

    assert result["insights"], "fixture must produce at least one insight"
    assert all(isinstance(i, str) for i in result["insights"])

    normalized = [normalize_insight(i) for i in result["insights"]]
    assert all(isinstance(n, dict) and "message" in n for n in normalized)

    # A caller that does supply structured insights keeps its fields.
    structured = {"message": "m", "priority": "HIGH", "icon": "x"}
    assert normalize_insight(structured) is structured
