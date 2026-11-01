#!/usr/bin/env python3
"""Rank what to work on next from GitHub issue state.

    python scripts/dev/backlog.py next [--json] [--top N]

Design: docs/superpowers/specs/2026-10-31-github-issue-planning-design.md (§5).
GitHub Issues are the single source: priority, phase and `needs:*` are labels,
ordering is native "blocked by" links, and a work package is a parent issue
whose sub-issues one PR closes. One `gh issue list --json` call reads it all;
everything after that is a pure function, unit-tested on recorded rows.

THE READY RULE
--------------
The ranking works on units: a package (an open issue with an open sub-issue)
or an open issue whose parent is not open. A child of an open package is shown
under it, never ranked on its own, so a blocked package hides its children
(GitHub does not propagate a parent's blockers; this does). A unit is ready
when it carries `priority:p1` or `priority:p2`, no `needs:*` label, none of the
never-ranked labels, no open blocker, and no assignee (assigned = in progress).
Ready units sort by priority, then lowest `phase:N` (none sorts last), then how
many open issues they unblock, then age.

Read-only, stdlib-only, and refuses gh older than 2.94 (the first with the
`parent`, `subIssuesSummary`, `blockedBy` and `blocking` JSON fields).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]

# Run directly (`python scripts/dev/backlog.py`) and sys.path[0] is
# scripts/dev, not the repo root. Same bootstrap as check_doc_links.py.
if __package__ in (None, ""):  # pragma: no cover - only on direct execution
    sys.path.insert(0, str(REPO_ROOT))

from scripts.core.unicode_utils import harden_console_streams  # noqa: E402

PRIORITIES = {"priority:p1": 1, "priority:p2": 2, "priority:p3": 3}
NEEDS = ("needs:decision", "needs:info")
NEVER_RANKED = ("tracking", "dependencies", "nightly-test-failure")
P1_SOFT_CAP = 7
MIN_GH = (2, 94, 0)
FETCH_LIMIT = 500
GH_FIELDS = (
    "number,title,labels,createdAt,assignees,parent,subIssuesSummary,blockedBy,blocking"
)
SUBPROCESS_TIMEOUT = 120
NO_PHASE = 10**6

_PHASE = re.compile(r"phase:(\d+)")
_GH_VERSION = re.compile(r"gh version (\d+)\.(\d+)\.(\d+)")


@dataclass(frozen=True)
class Item:
    number: int
    title: str
    labels: frozenset[str]
    created_at: datetime
    assignees: tuple[str, ...]
    parent: int | None
    sub_total: int
    sub_open: int
    open_blockers: tuple[int, ...]
    open_blocking: tuple[int, ...]

    @property
    def priority(self) -> int | None:
        """The highest priority among its labels; two labels never drop it."""
        found = [PRIORITIES[name] for name in self.labels if name in PRIORITIES]
        return min(found) if found else None

    @property
    def phase(self) -> int | None:
        found = [int(m.group(1)) for m in map(_PHASE.fullmatch, self.labels) if m]
        return min(found) if found else None

    @property
    def is_package(self) -> bool:
        return self.sub_open > 0


@dataclass
class Report:
    top: list[Item]
    in_progress: list[Item]
    decisions: list[tuple[Item, int]]
    biggest_unblocker: tuple[Item, int] | None
    close_candidates: list[Item]
    waiting_children: dict[int, list[Item]]
    untriaged: list[Item]
    needs_info: int
    parked_p3: int
    open_p1: int
    pending_suggestions: int
    truncated: bool
    top_n: int
    blocks: dict[int, int]


def _open_numbers(edge: dict[str, Any] | None) -> tuple[int, ...]:
    nodes = (edge or {}).get("nodes") or []
    return tuple(sorted(n["number"] for n in nodes if n.get("state") == "OPEN"))


def parse_items(rows: list[dict[str, Any]]) -> dict[int, Item]:
    items: dict[int, Item] = {}
    for row in rows:
        summary = row.get("subIssuesSummary") or {}
        total = int(summary.get("total") or 0)
        completed = int(summary.get("completed") or 0)
        items[row["number"]] = Item(
            number=row["number"],
            title=row.get("title") or "",
            labels=frozenset(lbl["name"] for lbl in row.get("labels") or []),
            created_at=datetime.fromisoformat(row["createdAt"]),
            assignees=tuple(a["login"] for a in row.get("assignees") or []),
            parent=(row.get("parent") or {}).get("number"),
            sub_total=total,
            sub_open=total - completed,
            open_blockers=_open_numbers(row.get("blockedBy")),
            open_blocking=_open_numbers(row.get("blocking")),
        )
    return items


def _is_child(item: Item, items: dict[int, Item]) -> bool:
    return item.parent is not None and item.parent in items


def units(items: dict[int, Item]) -> list[Item]:
    """Packages and issues whose parent is not open; children rank via them."""
    return [i for i in items.values() if i.is_package or not _is_child(i, items)]


def blocks_count(item: Item, items: dict[int, Item]) -> int:
    """Open issues it blocks; a blocked package counts as 1 + its open children.

    Direct links only, so a blocked-by cycle cannot loop.
    """
    count = 0
    for number in item.open_blocking:
        blocked = items.get(number)
        count += 1 + (blocked.sub_open if blocked and blocked.is_package else 0)
    return count


def _never_ranked(item: Item) -> bool:
    return any(name in item.labels for name in NEVER_RANKED)


def _waits(item: Item) -> bool:
    return any(name in item.labels for name in NEEDS) or bool(item.open_blockers)


def is_ready(item: Item) -> bool:
    return (
        item.priority in (1, 2)
        and not _waits(item)
        and not _never_ranked(item)
        and not item.assignees
    )


def rank(items: dict[int, Item]) -> list[Item]:
    ready = [
        u
        for u in units(items)
        if is_ready(u) and not (u.sub_total > 0 and u.sub_open == 0)
    ]
    return sorted(
        ready,
        key=lambda i: (
            i.priority,
            NO_PHASE if i.phase is None else i.phase,
            -blocks_count(i, items),
            i.created_at,
            i.number,
        ),
    )


def build_report(
    items: dict[int, Item],
    now: datetime,
    pending: int,
    top_n: int = 3,
    truncated: bool = False,
) -> Report:
    all_units = units(items)
    oldest_first = sorted(items.values(), key=lambda i: (i.created_at, i.number))

    blocks = {n: c for n, i in items.items() if (c := blocks_count(i, items)) > 0}
    unblockers = sorted(blocks.items(), key=lambda pair: (-pair[1], pair[0]))

    waiting: dict[int, list[Item]] = {}
    for child in sorted(items.values(), key=lambda i: i.number):
        parent = child.parent
        if parent is not None and parent in items and _waits(child):
            waiting.setdefault(parent, []).append(child)

    return Report(
        top=rank(items)[:top_n],
        in_progress=[u for u in all_units if u.assignees],
        decisions=[
            (i, (now - i.created_at).days)
            for i in oldest_first
            if "needs:decision" in i.labels
        ],
        biggest_unblocker=(
            (items[unblockers[0][0]], unblockers[0][1]) if unblockers else None
        ),
        close_candidates=[
            i for i in oldest_first if i.sub_total > 0 and i.sub_open == 0
        ],
        waiting_children=waiting,
        untriaged=[
            u
            for u in sorted(all_units, key=lambda i: i.number)
            if u.priority is None and not _never_ranked(u)
        ],
        needs_info=sum("needs:info" in i.labels for i in items.values()),
        parked_p3=sum(i.priority == 3 for i in items.values()),
        open_p1=sum(i.priority == 1 for i in items.values()),
        pending_suggestions=pending,
        truncated=truncated,
        top_n=top_n,
        blocks=blocks,
    )


def _describe(item: Item, items_blocked: int) -> str:
    notes = []
    if item.is_package:
        notes.append(f"{item.sub_open} open sub-issue(s)")
    if items_blocked:
        notes.append(f"unblocks {items_blocked}")
    phase = f"phase:{item.phase}" if item.phase is not None else "phase:-"
    tail = f"  ({', '.join(notes)})" if notes else ""
    return f"#{item.number} p{item.priority} {phase}  {item.title}{tail}"


def render_text(report: Report) -> str:
    lines: list[str] = []
    if report.truncated:
        lines.append(
            f"WARNING: fetched {FETCH_LIMIT} open issues, the limit: the list is "
            "truncated and the ranking may be partial."
        )
    lines.append(f"Top {report.top_n} ready")
    if not report.top:
        lines.append("  (none)")
    for n, item in enumerate(report.top, 1):
        lines.append(f"  {n}. {_describe(item, report.blocks.get(item.number, 0))}")
        for child in report.waiting_children.get(item.number, []):
            why = ", ".join(sorted(set(NEEDS) & child.labels)) or "blocked"
            lines.append(f"       waits: #{child.number} {child.title} ({why})")
    progress = ", ".join(f"#{i.number} {i.title}" for i in report.in_progress)
    lines.append(f"In progress: {progress or 'none'}")
    lines.append("Decisions waiting on you (oldest first)")
    if not report.decisions:
        lines.append("  (none)")
    for item, age in report.decisions:
        lines.append(f"  #{item.number} {age}d  {item.title}")
    if report.biggest_unblocker:
        item, count = report.biggest_unblocker
        lines.append(f"Biggest unblocker: #{item.number} (frees {count} issue(s))")
    else:
        lines.append("Biggest unblocker: none")
    for item in report.close_candidates:
        lines.append(f"Close it? #{item.number} {item.title} (every sub-issue closed)")
    lines.append(
        f"Untriaged: {len(report.untriaged)} | needs:info: {report.needs_info} | "
        f"p3 parked: {report.parked_p3} | pending suggestions: "
        f"{report.pending_suggestions} | open p1: {report.open_p1}/{P1_SOFT_CAP}"
    )
    return "\n".join(lines)


def _item_json(item: Item) -> dict[str, Any]:
    return {
        "number": item.number,
        "title": item.title,
        "priority": item.priority,
        "phase": item.phase,
        "sub_open": item.sub_open,
    }


def report_json(report: Report) -> dict[str, Any]:
    return {
        "top": [_item_json(i) for i in report.top],
        "in_progress": [i.number for i in report.in_progress],
        "decisions": [{"number": i.number, "age_days": a} for i, a in report.decisions],
        "biggest_unblocker": (
            {
                "number": report.biggest_unblocker[0].number,
                "blocks": report.biggest_unblocker[1],
            }
            if report.biggest_unblocker
            else None
        ),
        "close_candidates": [i.number for i in report.close_candidates],
        "waiting_children": {
            str(k): [c.number for c in v] for k, v in report.waiting_children.items()
        },
        "untriaged": [i.number for i in report.untriaged],
        "needs_info": report.needs_info,
        "parked_p3": report.parked_p3,
        "open_p1": report.open_p1,
        "p1_soft_cap": P1_SOFT_CAP,
        "pending_suggestions": report.pending_suggestions,
        "truncated": report.truncated,
    }


def _gh(*args: str, stdin: str | None = None) -> str:
    """Run `gh` and return stdout; a non-zero exit raises RuntimeError.

    Same contract as phase_audit._gh: utf-8 with errors="replace", since issue
    titles carry characters a Windows console code page cannot decode.
    """
    proc = subprocess.run(
        ["gh", *args],
        input=stdin,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=SUBPROCESS_TIMEOUT,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"gh {' '.join(args)} failed (rc={proc.returncode}):\n{proc.stderr.strip()}"
        )
    return proc.stdout


def require_gh(version_text: str) -> None:
    match = _GH_VERSION.search(version_text)
    found = tuple(int(g) for g in match.groups()) if match else None
    if found is None or found < MIN_GH:
        need = ".".join(map(str, MIN_GH))
        have = ".".join(map(str, found)) if found else "an unrecognised version"
        print(
            f"backlog: needs gh {need} or later (for sub-issue and blocked-by "
            f"fields); found {have}",
            file=sys.stderr,
        )
        raise SystemExit(2)


def fetch_items() -> tuple[dict[int, Item], bool]:
    raw = _gh(
        "issue",
        "list",
        "--state",
        "open",
        "--limit",
        str(FETCH_LIMIT),
        "--json",
        GH_FIELDS,
    )
    rows = json.loads(raw)
    return parse_items(rows), len(rows) >= FETCH_LIMIT


def main(argv: list[str] | None = None) -> int:
    harden_console_streams()
    parser = argparse.ArgumentParser(prog="backlog.py", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p_next = sub.add_parser("next", help="print the top ready items")
    p_next.add_argument("--json", action="store_true", dest="as_json")
    p_next.add_argument("--top", type=int, default=3)
    args = parser.parse_args(argv)

    try:
        require_gh(_gh("--version"))
        items, truncated = fetch_items()
    except (RuntimeError, OSError) as exc:
        print(f"backlog: gh failed: {' '.join(str(exc).split())}", file=sys.stderr)
        return 2

    report = build_report(
        items,
        now=datetime.now(UTC),
        pending=0,
        top_n=args.top,
        truncated=truncated,
    )
    if args.as_json:
        print(json.dumps(report_json(report), indent=2))
    else:
        print(render_text(report))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
