#!/usr/bin/env python3
"""`scan_tool_runs`: one row per target and tool, in history (#722).

`scans.duration_seconds` is one number for the whole scan, so "which tool made
my scan slow?" had no answer in JMo's own history. The scan's accounting rows
travel in `.scan_metadata.json` (`tool_runs`), and `store_scan` inserts them in
the same transaction as the scan.

The table is created by `init_database`, which `store_scan` runs on every
store, so a database written before it existed gains it on the next store.
Tested against every historical `scans` shape the suite builds (the 1.1.0
`CHECK (profile ...)` among them), because a table added to a database is only
safe if the database it is added to survives: `findings` and `scan_metadata`
cascade from `scans`, and so does this table.
"""

from __future__ import annotations

import argparse
import json
import logging
import sqlite3
from pathlib import Path

import pytest

from scripts.cli.history_commands import cmd_history_show
from scripts.core.history_db import get_connection, get_scan_tool_runs, store_scan
from scripts.core.scan_timings import Reason, State, ToolRun
from tests.unit.test_history_profile_column_drop import (
    LEGACY_SHAPES,
    _build_pre_v2_database,
)

ROWS = [
    ToolRun("trivy", State.RAN, seconds=12.5, exit_code=0, attempts=1, invocations=1),
    ToolRun("hadolint", State.SKIPPED, Reason.NO_DOCKERFILES),
    ToolRun(
        "semgrep",
        State.FAILED,
        Reason.TIMED_OUT,
        seconds=900.0,
        attempts=2,
        invocations=1,
    ),
]


def _results_dir(tmp_path: Path, tool_runs: list | None) -> Path:
    results = tmp_path / "results"
    (results / "summaries").mkdir(parents=True)
    finding = {
        "id": "f1",
        "severity": "HIGH",
        "tool": {"name": "trivy", "version": "0.74.0"},
        "ruleId": "CVE-2024-1",
        "location": {"path": "a.py", "startLine": 1},
        "message": "x",
    }
    (results / "summaries" / "findings.json").write_bytes(
        json.dumps({"findings": [finding]}).encode("utf-8")
    )
    meta: dict = {"tools": [r.tool for r in ROWS], "duration_seconds": 1.0}
    if tool_runs is not None:
        meta["tool_runs"] = tool_runs
    (results / ".scan_metadata.json").write_bytes(json.dumps(meta).encode("utf-8"))
    return results


def _entries(rows=ROWS, target="proj", target_type="repo") -> list[dict]:
    return [{"target": target, "target_type": target_type, **r.to_dict()} for r in rows]


def _stored(db: Path) -> list[tuple]:
    con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
    try:
        return con.execute(
            "SELECT target, target_type, tool, state, reason, seconds, exit_code, "
            "attempts FROM scan_tool_runs ORDER BY tool"
        ).fetchall()
    finally:
        con.close()


EXPECTED = [
    ("proj", "repo", "hadolint", "skipped", "no Dockerfiles", 0.0, None, 0),
    ("proj", "repo", "semgrep", "failed", "timed out", 900.0, None, 2),
    ("proj", "repo", "trivy", "ran", None, 12.5, 0, 1),
]


def test_every_row_is_stored_with_the_scan(tmp_path):
    db = tmp_path / "h.db"

    store_scan(_results_dir(tmp_path, _entries()), tools=["trivy"], db_path=db)

    assert _stored(db) == EXPECTED


def test_a_results_dir_from_before_the_rows_stores_none(tmp_path):
    db = tmp_path / "h.db"

    store_scan(_results_dir(tmp_path, None), tools=["trivy"], db_path=db)

    assert _stored(db) == []


def test_an_unreadable_row_is_skipped_and_said_not_fatal(tmp_path, caplog):
    """Losing one row must not lose the scan (the #901 lesson)."""
    db = tmp_path / "h.db"
    entries = _entries()
    entries.append(
        {"target": "proj", "target_type": "repo", "tool": "x", "state": "wrong"}
    )

    with caplog.at_level(logging.WARNING, logger="scripts.core.history_db"):
        store_scan(_results_dir(tmp_path, entries), tools=["trivy"], db_path=db)

    assert _stored(db) == EXPECTED
    assert "unreadable tool_runs row" in caplog.text


def test_a_repo_and_an_image_of_one_name_keep_a_row_each(tmp_path):
    """The key carries target_type: `app` the repo and `app` the IaC file are
    two targets, and one must not replace the other's row."""
    db = tmp_path / "h.db"
    trivy = [ROWS[0]]
    entries = _entries(trivy, "app", "repo") + _entries(trivy, "app", "iac")

    store_scan(_results_dir(tmp_path, entries), tools=["trivy"], db_path=db)

    assert sorted(r[:3] for r in _stored(db)) == [
        ("app", "iac", "trivy"),
        ("app", "repo", "trivy"),
    ]


def test_a_repeated_row_keeps_the_scan(tmp_path):
    """Two rows for one key cannot come from a scan (#1303 made names unique),
    but a hand-edited or merged metadata file must not fail the whole store."""
    db = tmp_path / "h.db"
    entries = _entries() + _entries([ROWS[0]])

    scan_id = store_scan(_results_dir(tmp_path, entries), tools=["trivy"], db_path=db)

    assert scan_id
    assert _stored(db) == EXPECTED


def test_deleting_a_scan_deletes_its_rows(tmp_path):
    db = tmp_path / "h.db"
    scan_id = store_scan(
        _results_dir(tmp_path, _entries()), tools=["trivy"], db_path=db
    )

    conn = get_connection(db)
    conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()

    assert _stored(db) == []


def test_the_state_and_reason_are_checked_by_the_database(tmp_path):
    """A `ran` row with a reason, a skip without one, or a state outside the
    three, is refused. Each case trips exactly one of the two CHECKs."""
    db = tmp_path / "h.db"
    scan_id = store_scan(_results_dir(tmp_path, None), tools=["trivy"], db_path=db)
    conn = get_connection(db)
    for state, reason in (
        ("ran", "timed out"),
        ("skipped", None),
        ("succeeded", "timed out"),
    ):
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO scan_tool_runs (scan_id, target, target_type, tool, state, "
                "reason) VALUES (?, 'p', 'repo', 'trivy', ?, ?)",
                (scan_id, state, reason),
            )
    conn.close()


@pytest.mark.parametrize("shape", [*LEGACY_SHAPES, "2.0.0"])
def test_a_database_from_before_the_table_gains_it_on_the_next_store(tmp_path, shape):
    """Every historical shape: the table is created, the rows stored, and the
    old scan's findings survive (a rebuild of `scans` would cascade them away)."""
    db = tmp_path / "old.db"
    _build_pre_v2_database(db, shape if shape != "2.0.0" else "1.2.0")
    conn = get_connection(db)
    if shape == "2.0.0":  # 1.2.0 after the v2 migration: no profile column
        conn.execute("DROP INDEX IF EXISTS idx_scans_profile")
        conn.execute("ALTER TABLE scans DROP COLUMN profile")
    conn.execute("DROP TABLE scan_tool_runs")  # as every database before Phase 3
    conn.commit()
    tables = {
        r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    conn.close()
    assert "scan_tool_runs" not in tables, "fixture still has the table"

    store_scan(_results_dir(tmp_path, _entries()), tools=["trivy"], db_path=db)

    assert _stored(db) == EXPECTED
    conn = get_connection(db)
    assert (
        conn.execute(
            "SELECT COUNT(*) FROM findings WHERE scan_id='old-scan'"
        ).fetchone()[0]
        == 3
    )
    assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    conn.close()


def _show(db: Path, scan_id: str, *, as_json: bool, capsys) -> tuple[int, str]:
    rc = cmd_history_show(
        argparse.Namespace(db=str(db), scan_id=scan_id, json=as_json, findings=False)
    )
    return rc, capsys.readouterr().out


def test_history_show_prints_each_tools_state_and_seconds(tmp_path, capsys):
    """#722's question, "why is my scan slow", answered from history."""
    db = tmp_path / "h.db"
    scan_id = store_scan(
        _results_dir(tmp_path, _entries()), tools=["trivy"], db_path=db
    )

    rc, out = _show(db, scan_id, as_json=False, capsys=capsys)

    assert rc == 0
    tools = out.split("Tool Runs:\n", 1)[1]
    assert "semgrep" in tools and "900.0s" in tools and "failed:timed out" in tools
    assert "trivy" in tools and "12.5s" in tools
    assert "skipped:no Dockerfiles" in tools
    assert "--json" not in tools, "a note about hidden rows when none were hidden"

    rc, out = _show(db, scan_id, as_json=True, capsys=capsys)
    assert rc == 0
    assert [r["tool"] for r in json.loads(out)["tool_runs"]] == [
        "hadolint",
        "semgrep",
        "trivy",
    ]


def test_history_show_hides_tools_that_do_not_read_the_target(tmp_path, capsys):
    """#1316: every requested tool has a row on every target, so an image
    target showed 12 lines, 10 of them tools that never read images. The text
    view keeps the rows about the target and counts the rest; --json keeps
    every row."""
    db = tmp_path / "h.db"
    repo = [
        ROWS[0],
        ToolRun("zap", State.SKIPPED, Reason.NEEDS_URL),
        ToolRun("nuclei", State.SKIPPED, Reason.NEEDS_URL),
    ]
    url = [
        ToolRun("zap", State.RAN, seconds=18.9, exit_code=0, attempts=1, invocations=1),
        ToolRun("trivy", State.SKIPPED, Reason.NOT_FOR_TARGET),
    ]
    entries = _entries(repo, "proj", "repo") + _entries(url, "https://a.test", "url")
    scan_id = store_scan(_results_dir(tmp_path, entries), tools=["trivy"], db_path=db)

    rc, out = _show(db, scan_id, as_json=False, capsys=capsys)

    assert rc == 0
    lines = out.split("Tool Runs:\n", 1)[1].split("\n\n", 1)[0].splitlines()
    shown = [ln.split()[:2] for ln in lines if not ln.lstrip().startswith("(")]
    assert sorted(shown) == [["https://a.test", "zap"], ["proj", "trivy"]]
    assert not [ln for ln in lines if "needs --url" in ln or "not for this" in ln]
    hidden = [ln for ln in lines if ln.lstrip().startswith("(")]
    assert len(hidden) == 1 and "3 " in hidden[0] and "--json" in hidden[0], lines

    rc, out = _show(db, scan_id, as_json=True, capsys=capsys)
    assert rc == 0
    assert len(json.loads(out)["tool_runs"]) == 5


def test_history_show_reads_a_database_that_has_no_table(tmp_path, capsys):
    """`history show` opens read-only, so it cannot create the table: a
    database no Phase 3 scan has stored into must still show."""
    db = tmp_path / "h.db"
    scan_id = store_scan(_results_dir(tmp_path, None), tools=["trivy"], db_path=db)
    conn = get_connection(db)
    conn.execute("DROP TABLE scan_tool_runs")
    conn.commit()
    conn.close()

    rc, out = _show(db, scan_id, as_json=False, capsys=capsys)

    assert rc == 0
    assert "Tool Runs:" not in out
    assert "Tools:           1 (trivy)" in out, "the scan itself did not show"
    assert get_scan_tool_runs(get_connection(db, read_only=True), scan_id) == []
