#!/usr/bin/env python3
"""Tests for `scripts/dev/backlog.py`.

`backlog.py next` answers "what should we work on next?" from GitHub state, so
the session-start skill shows its top 3 as the plan. A ranking that silently
drops an item, or ranks one that is blocked, waiting or already in progress,
puts the wrong work in front of the maintainer with nothing to say so.

Rows are built in the exact shapes `gh issue list --json` returns (captured
2026-11-01 with gh 2.103.0); see `RECORDED` and the `row()` helper. None of
these tests calls `gh` or the network.
"""

from __future__ import annotations

import io
import json
import sys
from datetime import UTC, datetime
from typing import Any

import pytest

from scripts.dev import backlog
from scripts.dev.backlog import (
    FETCH_LIMIT,
    GH_FIELDS,
    blocks_count,
    build_report,
    fetch_items,
    main,
    parse_items,
    rank,
    render_text,
    require_gh,
)

NOW = datetime(2026, 10, 31, tzinfo=UTC)

Pair = tuple[int, str]


def _node(number: int, state: str) -> dict[str, Any]:
    return {
        "id": f"I_{number}",
        "number": number,
        "state": state,
        "title": f"issue {number}",
        "url": f"https://github.com/o/r/issues/{number}",
    }


def row(
    n: int,
    *,
    labels: tuple[str, ...] = (),
    created: str = "2026-10-01T00:00:00Z",
    assignees: tuple[str, ...] = (),
    parent: Pair | None = None,
    sub: tuple[int, int] = (0, 0),
    blocked_by: tuple[Pair, ...] = (),
    blocking: tuple[Pair, ...] = (),
    title: str | None = None,
) -> dict[str, Any]:
    """One `gh issue list --json <GH_FIELDS>` row, every field in its real shape.

    `sub` is (total, completed); `parent`, `blocked_by` and `blocking` hold
    (number, "OPEN" | "CLOSED") pairs.
    """
    total, completed = sub
    return {
        "number": n,
        "title": title or f"issue {n}",
        "labels": [
            {"id": f"LA_{name}", "name": name, "description": "", "color": "ededed"}
            for name in labels
        ],
        "createdAt": created,
        "assignees": [{"id": f"U_{lg}", "login": lg, "name": ""} for lg in assignees],
        "parent": None if parent is None else _node(*parent),
        "subIssuesSummary": {
            "completed": completed,
            "percentCompleted": (100 * completed // total) if total else 0,
            "total": total,
        },
        "blockedBy": {
            "nodes": [_node(*p) for p in blocked_by],
            "totalCount": len(blocked_by),
        },
        "blocking": {
            "nodes": [_node(*p) for p in blocking],
            "totalCount": len(blocking),
        },
    }


def items_of(*rows: dict[str, Any]) -> dict[int, backlog.Item]:
    return parse_items(list(rows))


def numbers(items: list[backlog.Item]) -> list[int]:
    return [i.number for i in items]


P1, P2, P3 = "priority:p1", "priority:p2", "priority:p3"

# A `gh issue list --json` document as gh 2.103.0 prints it (2026-11-01): a
# child of an open package, an issue blocked by one open and one closed issue,
# and the package itself with 1 of 4 sub-issues closed.
RECORDED = """[
  {"assignees": [], "blockedBy": {"nodes": [], "totalCount": 0},
   "blocking": {"nodes": [], "totalCount": 0}, "createdAt": "2026-10-29T16:05:20Z",
   "labels": [{"id": "LA_a", "name": "bug", "description": "", "color": "d73a4a"}],
   "number": 11,
   "parent": {"id": "I_10", "number": 10, "state": "OPEN", "title": "pkg",
              "url": "https://github.com/o/r/issues/10"},
   "subIssuesSummary": {"completed": 0, "percentCompleted": 0, "total": 0},
   "title": "child"},
  {"assignees": [],
   "blockedBy": {"nodes": [
     {"id": "I_7", "number": 7, "state": "OPEN", "title": "a",
      "url": "https://github.com/o/r/issues/7"},
     {"id": "I_8", "number": 8, "state": "CLOSED", "title": "b",
      "url": "https://github.com/o/r/issues/8"}], "totalCount": 2},
   "blocking": {"nodes": [], "totalCount": 0}, "createdAt": "2026-10-20T09:00:00Z",
   "labels": [], "number": 12, "parent": null,
   "subIssuesSummary": {"completed": 0, "percentCompleted": 0, "total": 0},
   "title": "blocked"},
  {"assignees": [], "blockedBy": {"nodes": [], "totalCount": 0},
   "blocking": {"nodes": [], "totalCount": 0}, "createdAt": "2026-10-01T00:00:00Z",
   "labels": [], "number": 10, "parent": null,
   "subIssuesSummary": {"completed": 1, "percentCompleted": 25, "total": 4},
   "title": "pkg"}
]"""


def test_parse_items_reads_the_recorded_gh_shapes() -> None:
    items = parse_items(json.loads(RECORDED))

    assert items[11].parent == 10
    assert items[12].open_blockers == (7,)
    assert items[10].sub_open == 3
    assert items[10].is_package
    assert items[11].labels == frozenset({"bug"})


# --- ranking ----------------------------------------------------------------


def test_p1_ranks_above_p2_whatever_the_phase() -> None:
    items = items_of(row(1, labels=(P2, "phase:6")), row(2, labels=(P1, "phase:9")))

    assert numbers(rank(items)) == [2, 1]


def test_within_a_priority_lower_phase_then_more_blocked_then_older() -> None:
    items = items_of(
        row(1, labels=(P2, "phase:7"), created="2026-01-01T00:00:00Z"),
        row(2, labels=(P2, "phase:6"), created="2026-10-02T00:00:00Z"),
        row(
            3,
            labels=(P2, "phase:6"),
            created="2026-10-03T00:00:00Z",
            blocking=((4, "OPEN"),),
        ),
        row(4, labels=(P2, "phase:9"), blocked_by=((3, "OPEN"),)),
        row(5, labels=(P2, "phase:6"), created="2026-10-01T00:00:00Z"),
    )

    # phase 6 first; within it #3 unblocks one, then #5 is older than #2.
    # #4 is blocked, so it is not in the list at all.
    assert numbers(rank(items)) == [3, 5, 2, 1]


def test_no_priority_and_p3_are_never_ranked_but_counted() -> None:
    items = items_of(row(1), row(2, labels=(P3,)), row(3, labels=(P2,)))

    report = build_report(items, NOW, pending=0)

    assert numbers(report.top) == [3]
    assert numbers(report.untriaged) == [1]
    assert report.parked_p3 == 1


@pytest.mark.parametrize(
    "label",
    [
        "needs:decision",
        "needs:info",
        "tracking",
        "dependencies",
        "nightly-test-failure",
    ],
)
def test_needs_and_never_ranked_labels_exclude(label: str) -> None:
    items = items_of(row(1, labels=(P2, label)), row(2, labels=(P2,)))

    assert numbers(rank(items)) == [2]


def test_an_open_blocker_excludes_and_a_closed_one_does_not() -> None:
    items = items_of(
        row(1, labels=(P2,), blocked_by=((9, "OPEN"),)),
        row(2, labels=(P2,), blocked_by=((8, "CLOSED"),)),
    )

    assert numbers(rank(items)) == [2]


def test_an_assigned_unit_is_in_progress_not_ready() -> None:
    items = items_of(row(1, labels=(P2,), assignees=("someone",)), row(2, labels=(P2,)))

    report = build_report(items, NOW, pending=0)

    assert numbers(report.top) == [2]
    assert numbers(report.in_progress) == [1]


def test_children_of_an_open_package_are_not_ranked_on_their_own() -> None:
    items = items_of(
        row(10, labels=(P2,), sub=(2, 0)),
        # A child with its own p1 still ranks only through its package.
        row(11, labels=(P1,), parent=(10, "OPEN")),
        row(12, parent=(10, "OPEN")),
    )

    assert numbers(rank(items)) == [10]


def test_a_blocked_package_hides_its_children() -> None:
    children = [row(n, labels=(P2,), parent=(30, "OPEN")) for n in (31, 32, 33, 34)]
    items = items_of(
        row(20, labels=(P2,), sub=(1, 0), blocking=((30, "OPEN"),)),
        row(21, parent=(20, "OPEN")),
        row(30, labels=(P2,), sub=(4, 0), blocked_by=((20, "OPEN"),)),
        *children,
    )

    assert numbers(build_report(items, NOW, pending=0, top_n=10).top) == [20]


def test_a_child_whose_parent_is_closed_is_standalone() -> None:
    items = items_of(row(40, labels=(P2,), parent=(39, "CLOSED")))

    assert numbers(rank(items)) == [40]


def test_a_package_with_a_waiting_child_is_ready_and_names_the_child() -> None:
    items = items_of(
        row(50, labels=(P2,), sub=(3, 0)),
        row(51, labels=("needs:decision",), parent=(50, "OPEN")),
        row(52, parent=(50, "OPEN")),
        row(53, parent=(50, "OPEN"), blocked_by=((99, "OPEN"),)),
    )

    report = build_report(items, NOW, pending=0)

    assert numbers(report.top) == [50]
    assert {k: numbers(v) for k, v in report.waiting_children.items()} == {50: [51, 53]}


def test_a_package_with_no_open_children_is_a_close_candidate_not_ranked() -> None:
    items = items_of(row(60, labels=(P2,), sub=(3, 3)), row(61, labels=(P2,)))

    report = build_report(items, NOW, pending=0)

    assert numbers(report.top) == [61]
    assert numbers(report.close_candidates) == [60]


def test_blocks_count_counts_a_blocked_package_as_one_plus_its_open_children() -> None:
    items = items_of(
        row(20, labels=(P2,), blocking=((30, "OPEN"), (35, "CLOSED"))),
        row(30, labels=(P2,), sub=(4, 0), blocked_by=((20, "OPEN"),)),
    )

    assert blocks_count(items[20], items) == 5


def test_biggest_unblocker_can_be_an_unready_decision_issue() -> None:
    items = items_of(
        row(
            70,
            labels=(P2, "needs:decision"),
            title="Decide: which",
            blocking=((71, "OPEN"), (72, "OPEN")),
        ),
        row(71, labels=(P2,), blocked_by=((70, "OPEN"),)),
        row(72, labels=(P2,), blocked_by=((70, "OPEN"),)),
        row(73, labels=(P1,)),
    )

    report = build_report(items, NOW, pending=0)

    assert numbers(report.top) == [73]
    assert report.biggest_unblocker is not None
    assert (report.biggest_unblocker[0].number, report.biggest_unblocker[1]) == (70, 2)


def test_untriaged_excludes_never_ranked_labels_and_package_children() -> None:
    items = items_of(
        row(80),
        row(81, labels=("tracking",)),
        row(82, labels=("dependencies",)),
        row(83, labels=(P2,), sub=(1, 0)),
        row(84, parent=(83, "OPEN")),
        row(85, labels=("nightly-test-failure",)),
    )

    assert numbers(build_report(items, NOW, pending=0).untriaged) == [80]


def test_decisions_are_oldest_first_with_age_in_days() -> None:
    items = items_of(
        row(90, labels=("needs:decision",), created="2026-10-21T00:00:00Z"),
        row(91, labels=("needs:decision",), created="2026-10-08T00:00:00Z"),
    )

    report = build_report(items, NOW, pending=0)

    assert [(i.number, age) for i, age in report.decisions] == [(91, 23), (90, 10)]


# --- Review Focus -----------------------------------------------------------


def test_contradictory_priorities_rank_by_the_highest() -> None:
    items = items_of(row(1, labels=(P1, P2, "phase:9")), row(2, labels=(P2, "phase:6")))

    assert items[1].priority == 1
    assert numbers(rank(items)) == [1, 2]


def test_a_blocked_by_cycle_terminates_and_neither_is_ready() -> None:
    items = items_of(
        row(1, labels=(P2,), blocked_by=((2, "OPEN"),), blocking=((2, "OPEN"),)),
        row(2, labels=(P2,), blocked_by=((1, "OPEN"),), blocking=((1, "OPEN"),)),
    )

    report = build_report(items, NOW, pending=0)

    assert report.top == []
    assert blocks_count(items[1], items) == 1


def test_non_numeric_phase_is_ignored_and_lowest_phase_wins() -> None:
    items = items_of(
        row(
            1,
            labels=(P2, "phase:x", "phase:7", "phase:5"),
            created="2026-10-09T00:00:00Z",
        ),
        # Older, but with no numeric phase it sorts after every phase.
        row(2, labels=(P2, "phase:x"), created="2026-01-01T00:00:00Z"),
    )

    assert items[1].phase == 5
    assert items[2].phase is None
    assert numbers(rank(items)) == [1, 2]


# --- output -----------------------------------------------------------------


def test_render_text_has_every_section() -> None:
    items = items_of(
        row(1, labels=(P1, "phase:6"), title="Phase 6 PR G: grype leaves"),
        row(2, labels=(P2,), assignees=("someone",)),
        row(3, labels=("needs:decision",), blocking=((4, "OPEN"),)),
        row(4, labels=(P2,), blocked_by=((3, "OPEN"),)),
    )

    text = render_text(build_report(items, NOW, pending=2))

    for section in (
        "Top 3 ready",
        "#1",
        "In progress",
        "#2",
        "Decisions waiting on you",
        "#3",
        "Biggest unblocker",
        "open p1: 1/7",
        "pending suggestions: 2",
    ):
        assert section in text


def test_main_prints_a_non_ascii_title_to_a_cp1252_console(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # U+2192 has no cp1252 byte: printing it unhardened raises UnicodeEncodeError.
    rows = [row(1, labels=(P1,), title="grype → osv-scanner")]
    monkeypatch.setattr(backlog, "_gh", _fake_gh(rows))
    buffer = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(buffer, encoding="cp1252"))

    assert main(["next"]) == 0

    sys.stdout.flush()
    assert b"grype ? osv-scanner" in buffer.getvalue()


def test_next_json_carries_the_ranking(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    rows = [row(1, labels=(P2,)), row(2, labels=(P1,)), row(3)]
    monkeypatch.setattr(backlog, "_gh", _fake_gh(rows))

    assert main(["next", "--json"]) == 0

    data = json.loads(capsys.readouterr().out)
    assert [i["number"] for i in data["top"]] == [2, 1]
    assert data["untriaged"] == [3]


# --- gh boundary ------------------------------------------------------------


def _fake_gh(rows: list[dict[str, Any]], calls: list[tuple[str, ...]] | None = None):
    def fake(*args: str, stdin: str | None = None) -> str:
        if calls is not None:
            calls.append(args)
        if args == ("--version",):
            return "gh version 2.103.0 (2026-10-21)\nhttps://github.com/cli/cli\n"
        if args[:2] == ("issue", "list"):
            return json.dumps(rows)
        raise AssertionError(f"unexpected gh call: {args}")

    return fake


@pytest.mark.parametrize(
    ("text", "ok"),
    [
        ("gh version 2.46.0 (2024-03-26)\nhttps://github.com/cli/cli\n", False),
        ("gh version 2.94.0 (2026-06-01)\n", True),
        ("gh version 2.103.0 (2026-10-21)\n", True),
        ("not gh at all\n", False),
    ],
    ids=["2.46-debian", "2.94-floor", "2.103", "unparseable"],
)
def test_require_gh_rejects_2_46_and_accepts_2_94_and_2_103(
    text: str, ok: bool, capsys: pytest.CaptureFixture[str]
) -> None:
    if ok:
        require_gh(text)
        return
    with pytest.raises(SystemExit) as exc:
        require_gh(text)
    assert exc.value.code == 2
    assert "2.94" in capsys.readouterr().err


def test_fetch_items_passes_list_args_and_flags_truncation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []
    rows = [row(n, labels=(P2,)) for n in range(1, FETCH_LIMIT + 1)]
    monkeypatch.setattr(backlog, "_gh", _fake_gh(rows, calls))

    items, truncated = fetch_items()

    assert calls == [
        ("issue", "list", "--state", "open", "--limit", "500", "--json", GH_FIELDS)
    ]
    assert len(items) == FETCH_LIMIT
    assert truncated is True
    text = render_text(build_report(items, NOW, pending=0, truncated=truncated))
    assert "truncated" in text


@pytest.mark.parametrize(
    "error",
    [
        FileNotFoundError(2, "No such file or directory", "gh"),
        RuntimeError(
            "gh issue list failed (rc=4):\nTo get started, run: gh auth login"
        ),
    ],
    ids=["gh-missing", "unauthenticated"],
)
def test_gh_failure_exits_2_with_one_line_on_stderr(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    error: Exception,
) -> None:
    def failing(*args: str, stdin: str | None = None) -> str:
        raise error

    monkeypatch.setattr(backlog, "_gh", failing)

    assert main(["next"]) == 2

    err = capsys.readouterr().err
    assert err.startswith("backlog: gh failed")
    assert err.count("\n") == 1
    assert "Traceback" not in err
