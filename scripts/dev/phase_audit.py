#!/usr/bin/env python3
"""
Answer "is this issue scheduled?" mechanically, from the fix-program plan.

Three sessions in a row filed issues that nothing scheduled. The bar that was
supposed to catch them - "every open issue carries a disposition before the
tag" - was true when chunk 22 closed and decayed silently, because nothing
re-checked it. Every check since has been a hand-maintained list, and the one
written at Phase 2 closeout silently omitted an issue. A mirror of a mirror.

This module removes the hand-maintained list. The plan is the single source of
truth; the phase labels on GitHub are a *projection* of it, and `verify`
asserts the projection still matches.

Four commands:

  derive     parse the plan, print the phase -> issue mapping, assert its
             internal checksums. No network.
  labels     create `phase:0`..`phase:N` and apply them to the plan's issues.
  unclaimed  open issues the plan does not mention at all. Exit 1 if any.
  verify     unclaimed + label drift, in both directions. Exit 1 if either.

Why the plan and not the labels are authoritative: a label can be added or
removed on github.com with no record of why, and there is no review on it. The
plan is a tracked file whose edits arrive through a PR. When the two disagree,
`verify` reports it rather than picking a winner.

WHY THE PARSE ASSERTS RATHER THAN TRUSTS
----------------------------------------
A regex over prose is a guess about formatting. So this does not rely on the
regex being right - it relies on four independently written numbers agreeing:

  1. each phase's own `**N issues:**` prefix, against the count parsed from
     that phase's roster;
  2. the per-phase `n` column of the Phase summary table, against the same;
  3. the table's `before tag` total, against the sum;
  4. no issue in two phases.

A roster that soft-wraps differently, a phase that loses its list, or an issue
silently dropped from a roster breaks at least one of these. A parse that
merely "found some numbers" cannot pass all four by accident.

Exit codes: 0 = agreement, 1 = a real disagreement, 2 = the plan could not be
parsed (which is itself a failure, never a skip).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Run directly (`python scripts/dev/phase_audit.py`) and sys.path[0] is
# scripts/dev, not the repo root. Same bootstrap as check_doc_links.py.
if __package__ in (None, ""):  # pragma: no cover - only on direct execution
    sys.path.insert(0, str(REPO_ROOT))

DEFAULT_PLAN = (
    REPO_ROOT
    / "docs"
    / "superpowers"
    / "plans"
    / "2026-08-22-v1.1.0-pre-release-fix-program.md"
)

LABEL_PREFIX = "phase:"
LABEL_COLOR = "0e8a16"

# `## Phase 3 — One-liners and single-site fixes`
_PHASE_HEADING = re.compile(r"^## Phase (\d+)\b", re.MULTILINE)

# Any level-2 heading. Roster searches are bounded by these rather than by the
# next *phase* heading: the last phase in the plan is followed by `## After the
# tag`, so a phase that lost its roster would otherwise absorb the after-tag
# list and schedule 20 post-tag features as phase work. Found by the negative
# control for a missing roster, which passed for the wrong reason.
_ANY_HEADING = re.compile(r"^## ", re.MULTILINE)

# `**17 issues:**`, `**6 issues, in this order:**`, `**1 issue:**`
_ROSTER_MARKER = re.compile(r"^\*\*(\d+) issues?\b[^*]*\*\*")

# `**15 issues, deliberately not phase work.**` under `## After the tag`
_AFTER_TAG_HEADING = re.compile(r"^## After the tag\b", re.MULTILINE)

# `| 0 — instruments | 16 | every later measurement | **DONE** ... |`
# The separator is an em dash; a hyphen here means the table was hand-edited
# with the wrong character, which is worth failing on rather than tolerating.
_SUMMARY_ROW = re.compile(r"^\|\s*(\d+)\s*—[^|]*\|\s*(\d+)\s*\|", re.MULTILINE)

# `| **before tag** | **92** | | |`
_SUMMARY_TOTAL = re.compile(
    r"^\|\s*\*\*before tag\*\*\s*\|\s*\*\*(\d+)\*\*", re.MULTILINE
)

# `| after tag | 20 | not phase work | |`
_SUMMARY_AFTER_TAG = re.compile(r"^\|\s*after tag\s*\|\s*(\d+)\s*\|", re.MULTILINE)

_ISSUE_REF = re.compile(r"#(\d+)")


class PlanParseError(RuntimeError):
    """The plan did not parse, or its own numbers disagree.

    Never downgraded to a warning. A plan that cannot be parsed is a plan
    nothing is checking, which is the failure this module exists to prevent.
    """


@dataclass(frozen=True)
class PlanIndex:
    """Everything the plan says about scheduling, with its checksums verified."""

    phases: dict[int, list[int]]
    after_tag: list[int]
    summary_total: int
    summary_after_tag: int
    path: Path

    @property
    def scheduled(self) -> set[int]:
        return {n for issues in self.phases.values() for n in issues}

    @property
    def all_known(self) -> set[int]:
        return self.scheduled | set(self.after_tag)

    def phase_of(self, issue: int) -> int | None:
        for phase, issues in self.phases.items():
            if issue in issues:
                return phase
        return None

    def label_for(self, issue: int) -> str | None:
        phase = self.phase_of(issue)
        return None if phase is None else f"{LABEL_PREFIX}{phase}"


def _roster_after(lines: list[str], marker_index: int) -> tuple[int, list[int]]:
    """Read one roster: the marker line plus continuations, to the blank line.

    Rosters are written three ways in this plan and all three must work:
    the marker alone with the list on the next line (Phase 0), the marker and
    list on one line (Phase 1), and a list that soft-wraps across two lines
    (Phase 6). Taking "marker through next blank line" covers all three, and
    the declared count is what catches it when a fourth shape appears.
    """
    marker = _ROSTER_MARKER.match(lines[marker_index])
    if marker is None:  # pragma: no cover - callers locate the line by this regex
        raise PlanParseError(
            f"line {marker_index + 1} is not a roster marker: {lines[marker_index]!r}"
        )
    declared = int(marker.group(1))
    chunk: list[str] = []
    for line in lines[marker_index:]:
        if not line.strip():
            break
        chunk.append(line)
    issues = [int(m) for m in _ISSUE_REF.findall(" ".join(chunk))]
    return declared, issues


def _section_ends(text: str, total_lines: int) -> dict[int, int]:
    """Map each `## ` heading's line index to the line index of the next one."""
    starts = [text[: m.start()].count("\n") for m in _ANY_HEADING.finditer(text)]
    return {
        start: (starts[i + 1] if i + 1 < len(starts) else total_lines)
        for i, start in enumerate(starts)
    }


def _find_roster(lines: list[str], start: int, stop: int) -> int:
    for i in range(start, stop):
        if _ROSTER_MARKER.match(lines[i]):
            return i
    raise PlanParseError(
        f"no `**N issues:**` roster found in the section starting at line "
        f"{start + 1} (`{lines[start].strip()}`)"
    )


def parse_plan(text: str, path: Path = DEFAULT_PLAN) -> PlanIndex:
    """Parse the plan and verify its four internal checksums.

    Raises PlanParseError on any disagreement. The caller is expected to let
    that propagate: a silent fallback here would reintroduce exactly the
    hand-maintained list this replaces.
    """
    lines = text.splitlines()
    section_ends = _section_ends(text, len(lines))

    heading_at: list[tuple[int, int]] = []  # (line index, phase number)
    for m in _PHASE_HEADING.finditer(text):
        heading_at.append((text[: m.start()].count("\n"), int(m.group(1))))
    if not heading_at:
        raise PlanParseError(f"{path}: no `## Phase N` headings found")

    phases: dict[int, list[int]] = {}
    declared: dict[int, int] = {}
    for line_no, phase in heading_at:
        idx = _find_roster(lines, line_no, section_ends[line_no])
        n, issues = _roster_after(lines, idx)
        if phase in phases:
            raise PlanParseError(f"{path}: `## Phase {phase}` appears twice")
        phases[phase], declared[phase] = issues, n

    problems: list[str] = []

    # Checksum 1 - each phase's own declared count.
    for phase, issues in sorted(phases.items()):
        if len(issues) != declared[phase]:
            problems.append(
                f"Phase {phase}: roster says `**{declared[phase]} issues**` but "
                f"{len(issues)} were parsed: {_fmt(issues)}"
            )

    # Checksum 4 - no issue scheduled twice. Checked before the totals so a
    # duplicate is reported as itself rather than as an arithmetic error.
    seen: dict[int, int] = {}
    for phase, issues in sorted(phases.items()):
        for n in issues:
            if n in seen:
                problems.append(f"#{n} is in both Phase {seen[n]} and Phase {phase}")
            seen[n] = phase

    # Checksum 2 - the Phase summary table's per-phase `n` column.
    table = {int(a): int(b) for a, b in _SUMMARY_ROW.findall(text)}
    for phase, issues in sorted(phases.items()):
        if phase not in table:
            problems.append(f"Phase {phase} has no row in the Phase summary table")
        elif table[phase] != len(issues):
            problems.append(
                f"Phase {phase}: summary table says {table[phase]}, roster has "
                f"{len(issues)}"
            )
    for phase in sorted(set(table) - set(phases)):
        problems.append(
            f"the summary table has a row for Phase {phase} with no `## Phase "
            f"{phase}` section"
        )

    # Checksum 3 - the `before tag` total.
    total_m = _SUMMARY_TOTAL.search(text)
    if total_m is None:
        raise PlanParseError(f"{path}: no `| **before tag** | **N** |` row found")
    summary_total = int(total_m.group(1))
    derived_total = sum(len(v) for v in phases.values())
    if derived_total != summary_total:
        problems.append(
            f"`before tag` says {summary_total}, the phase rosters sum to "
            f"{derived_total}"
        )

    after_tag, summary_after_tag = _parse_after_tag(
        text, lines, section_ends, path, problems
    )

    if problems:
        raise PlanParseError(
            f"{path}: the plan disagrees with itself\n  - " + "\n  - ".join(problems)
        )

    return PlanIndex(
        phases=phases,
        after_tag=after_tag,
        summary_total=summary_total,
        summary_after_tag=summary_after_tag,
        path=path,
    )


def _parse_after_tag(
    text: str,
    lines: list[str],
    section_ends: dict[int, int],
    path: Path,
    problems: list[str],
) -> tuple[list[int], int]:
    heading = _AFTER_TAG_HEADING.search(text)
    if heading is None:
        raise PlanParseError(f"{path}: no `## After the tag` section found")
    start = text[: heading.start()].count("\n")
    idx = _find_roster(lines, start, section_ends[start])
    declared, issues = _roster_after(lines, idx)
    if len(issues) != declared:
        problems.append(
            f"After the tag: roster says `**{declared} issues**` but "
            f"{len(issues)} were parsed: {_fmt(issues)}"
        )
    row = _SUMMARY_AFTER_TAG.search(text)
    if row is None:
        problems.append("no `| after tag | N |` row in the Phase summary table")
        return issues, declared
    if int(row.group(1)) != len(issues):
        problems.append(
            f"After the tag: summary table says {row.group(1)}, roster has "
            f"{len(issues)}"
        )
    return issues, int(row.group(1))


def _fmt(issues: list[int]) -> str:
    return " ".join(f"#{n}" for n in issues)


def load_plan(path: Path = DEFAULT_PLAN) -> PlanIndex:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:  # pragma: no cover - filesystem failure
        raise PlanParseError(f"{path}: {exc}") from exc
    return parse_plan(text, path)


# ---------------------------------------------------------------------------
# GitHub half. Isolated so the parser above stays testable without a network.
# ---------------------------------------------------------------------------


@dataclass
class Issue:
    number: int
    state: str
    labels: set[str] = field(default_factory=set)


def _gh(*args: str) -> str:
    """Run `gh` and return stdout.

    `encoding="utf-8", errors="replace"` is not decoration: issue titles in
    this repo carry bytes that are not representable in the Windows console's
    cp1252, and `text=True` raises UnicodeDecodeError on them.
    """
    proc = subprocess.run(
        ["gh", *args],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"gh {' '.join(args)} failed (rc={proc.returncode}):\n{proc.stderr.strip()}"
        )
    return proc.stdout


def fetch_issues(state: str = "all", limit: int = 1000) -> dict[int, Issue]:
    raw = _gh(
        "issue",
        "list",
        "--state",
        state,
        "--limit",
        str(limit),
        "--json",
        "number,state,labels",
    )
    out: dict[int, Issue] = {}
    for row in json.loads(raw):
        out[row["number"]] = Issue(
            number=row["number"],
            state=row["state"].upper(),
            labels={lbl["name"] for lbl in row["labels"]},
        )
    return out


@dataclass
class MergedPR:
    """A merged PR and the two disagreeing views of what it closed.

    `named` is what the body claims; `linked` is what GitHub actually recorded
    in `closingIssuesReferences`. A gap between them is a keyword that will
    never fire - most often because the PR's base was not the default branch,
    which is the only condition under which GitHub records nothing at all.
    """

    number: int
    base: str
    merged_at: str
    named: set[int] = field(default_factory=set)
    linked: set[int] = field(default_factory=set)


def fetch_merged_prs(limit: int = 1000) -> list[MergedPR]:
    raw = _gh(
        "pr",
        "list",
        "--state",
        "merged",
        "--limit",
        str(limit),
        "--json",
        "number,baseRefName,body,mergedAt,closingIssuesReferences",
    )
    return [
        MergedPR(
            number=row["number"],
            base=row["baseRefName"],
            merged_at=(row.get("mergedAt") or "")[:10],
            named=closing_keywords(row.get("body") or ""),
            linked={ref["number"] for ref in row["closingIssuesReferences"]},
        )
        for row in json.loads(raw)
    ]


def inert_closers(
    prs: list[MergedPR], issues: dict[int, Issue]
) -> list[tuple[MergedPR, list[int]]]:
    """Merged PRs whose body named an OPEN issue GitHub never linked.

    This is the half of the fixed-but-open population that the phase rosters
    cannot see. `cmd_closers` derives "fixed" from "the issue's phase landed",
    so anything fixed before the phase program existed - the whole 22-chunk
    campaign - is outside it. Measured: `a45e5b4` (PR #793, base `dev`) closed
    #787 through #791 in its body on 2026-08-09 and all five sat open for
    seventeen days while the gate printed `MISSING: 0`.

    The discriminator is `named - linked`, NOT "the base was not `main`". It
    measures the state GitHub recorded instead of inferring it from a branch
    name, so it also catches a PR that linked three of the five issues it
    named. Restricting to numbers present in `issues` is what makes it precise:
    six merged PRs in this repo say `Closes #N` about another PULL REQUEST,
    GitHub correctly records no closing reference, and `gh issue list` does not
    return PRs - so the map lookup drops all six without a special case.
    """
    found: list[tuple[MergedPR, list[int]]] = []
    for pr in prs:
        gap = sorted(
            n for n in pr.named - pr.linked if n in issues and issues[n].state == "OPEN"
        )
        if gap:
            found.append((pr, gap))
    return sorted(found, key=lambda row: row[0].number)


def _phase_labels(issue: Issue) -> set[str]:
    return {name for name in issue.labels if name.startswith(LABEL_PREFIX)}


def _git(*args: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed (rc={proc.returncode}):\n{proc.stderr.strip()}"
        )
    return proc.stdout


# `Phase 2 — Delete before refactor (4 issues) (#997)`, as squashed onto `dev`.
# Git is the authority on what landed; the plan's `**DONE**` column is prose
# a session writes about itself.
#
# The optional conventional-commit prefix is load-bearing, not tolerance for
# sloppiness. Phase 6 squashed as `fix: Phase 6 - subsystems ...` and Phase 7 as
# `fix(dashboard): Phase 7 - ...`, so a bare `^Phase` anchor reported
# `[0, 1, 2, 3, 4, 5, 8]` and dropped both phases from the fixed-but-open
# population. It gave the right answer only because every Phase 6 and 7 issue
# happened to be closed by then; one of them without a closing keyword would
# have synced to `main` still open, behind `MISSING: 0`.
#
# The prefix is ANCHORED, never skipped over. Dropping the `^` makes three real
# subjects report a phase that never landed - measured across all 1165 subjects
# in this repository, these are the only three, and all three are on `dev`:
#
#   feat(dedup): complete cross-tool deduplication (Phase 0-9)       -> phase 0
#   feat(dedup): implement cross-tool deduplication (Phase 0-7)      -> phase 0
#   feat(wizard): implement Feature #4 Phase 1 - Enhanced workflows  -> phase 1
#
# Phases 0 and 1 have both landed, so the resulting SET is unchanged and the
# defect is invisible in the aggregate. That is why the guard asserts each
# subject alone.
_PHASE_SUBJECT = re.compile(
    r"^(?:[a-z]+(?:\([^()]*\))?!?:[ \t]*)?Phase (\d+)\s*[—-]", re.MULTILINE
)

# `Closes #960`, `fixes #12`, `Resolved: #3`. Case-insensitive: a
# `grep 'closes #'` misses every capitalised one, which is how #538 was missed.
#
# The separator is `[ \t]*:?[ \t]*` and NOT `\s` or `[^\w#]`, because those
# match across a sentence break that GitHub does not close on. A permissive
# version of this regex read `"...and those are what this fixes.\n\n#976 item 1"`
# in `1d8a916` as closing #976, and reported an issue as covered when nothing
# would close it - a false negative in the check, which is the direction that
# ships the bug.
_CLOSING_KEYWORD = re.compile(
    r"\b(?:close[sd]?|fixe[sd]?|fix|resolve[sd]?)\b[ \t]*:?[ \t]*#(\d+)", re.IGNORECASE
)


def phases_in_subjects(text: str) -> set[int]:
    """Phase numbers named by a squash subject in `text`, one subject per line.

    Split out from `landed_phases` so the recognition rule is testable without
    a repository: the same separation `closing_keywords` already has from
    `keywords_in_range`, and for the same reason. The 22 tests this module had
    before covered the plan parser and the label projection, and not one of
    them could see that two landed phases were going unrecognised.
    """
    return {int(m) for m in _PHASE_SUBJECT.findall(text)}


def landed_phases(ref: str = "origin/dev") -> set[int]:
    """Phase numbers whose squash commit is reachable from `ref`.

    Raises if it finds none: an extractor that silently returns nothing
    satisfies every assertion built on it, which is the shape that let the
    unclaimed-issue bar decay in the first place.
    """
    found = phases_in_subjects(_git("log", ref, "--format=%s"))
    if not found:
        raise RuntimeError(
            f"no `Phase N — ...` commit subjects found on {ref}. Either the "
            "phase-commit naming changed or the ref is wrong - both are real "
            "failures, not an empty result."
        )
    return found


def closing_keywords(text: str) -> set[int]:
    """Issue numbers this text would close if it reached the default branch."""
    return {int(m) for m in _CLOSING_KEYWORD.findall(text)}


def keywords_in_range(rev_range: str) -> set[int]:
    return closing_keywords(_git("log", rev_range, "--format=%B"))


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_derive(plan: PlanIndex, as_json: bool) -> int:
    if as_json:
        print(
            json.dumps(
                {
                    "phases": {str(k): v for k, v in sorted(plan.phases.items())},
                    "after_tag": plan.after_tag,
                    "before_tag_total": plan.summary_total,
                    "after_tag_total": plan.summary_after_tag,
                },
                indent=2,
            )
        )
        return 0
    for phase, issues in sorted(plan.phases.items()):
        print(f"phase:{phase:<2} n={len(issues):<3} {_fmt(issues)}")
    print(f"after-tag  n={len(plan.after_tag):<3} {_fmt(plan.after_tag)}")
    print(
        f"\nbefore tag {plan.summary_total} + after tag {plan.summary_after_tag} "
        f"= {plan.summary_total + plan.summary_after_tag} issues known to the plan"
    )
    print("all four plan checksums agree")
    return 0


def cmd_labels(plan: PlanIndex, apply: bool) -> int:
    issues = fetch_issues()
    wanted = {LABEL_PREFIX + str(p) for p in plan.phases}
    existing = {
        row["name"]
        for row in json.loads(_gh("label", "list", "--limit", "200", "--json", "name"))
    }
    to_create = sorted(wanted - existing, key=lambda s: int(s.split(":")[1]))
    for name in to_create:
        number_part = name.split(":")[1]
        print(f"{'create' if apply else 'would create'} label {name}")
        if apply:
            _gh(
                "label",
                "create",
                name,
                "--color",
                LABEL_COLOR,
                "--description",
                f"v1.1.0 fix program, phase {number_part}",
            )

    # Iterate the phases rather than `plan.scheduled` so `want` is a plain str.
    # `label_for()` returns `str | None` for issues the plan does not schedule,
    # and mypy is right to insist the difference is handled somewhere.
    adds = removes = 0
    for phase, numbers in sorted(plan.phases.items()):
        want = f"{LABEL_PREFIX}{phase}"
        for number in sorted(numbers):
            issue = issues.get(number)
            if issue is None:
                print(f"  SKIP #{number}: the plan schedules it but it does not exist")
                continue
            have = _phase_labels(issue)
            stale = sorted(have - {want})
            if want not in have:
                adds += 1
                print(f"  {'+' if apply else '~'} #{number} {want}")
                if apply:
                    _gh("issue", "edit", str(number), "--add-label", want)
            for name in stale:
                removes += 1
                print(f"  {'-' if apply else '~'} #{number} drop {name}")
                if apply:
                    _gh("issue", "edit", str(number), "--remove-label", name)
    verb = "applied" if apply else "would apply"
    print(
        f"\n{verb}: {adds} label(s) added, {removes} removed, {len(to_create)} created"
    )
    if not apply:
        print("dry run - pass --apply to write")
    return 0


def cmd_unclaimed(plan: PlanIndex) -> int:
    issues = fetch_issues(state="open")
    survivors = sorted(set(issues) - plan.all_known)
    if not survivors:
        print(f"unclaimed: 0 of {len(issues)} open issues are absent from the plan")
        return 0
    print(
        f"::error::{len(survivors)} open issue(s) are in no phase and not in the "
        "'After the tag' list, so the tag would miss them:"
    )
    for number in survivors:
        print(f"  #{number}")
    print(
        "\nGive each one a home in "
        f"{plan.path.relative_to(REPO_ROOT).as_posix()} - a phase roster or the "
        "'After the tag' list - then re-run. A label alone is not a home; the "
        "plan is the source and the labels are derived from it."
    )
    return 1


def cmd_verify(plan: PlanIndex) -> int:
    issues = fetch_issues()
    rc = 0

    open_numbers = {n for n, i in issues.items() if i.state == "OPEN"}
    survivors = sorted(open_numbers - plan.all_known)
    if survivors:
        rc = 1
        print(f"::error::unclaimed open issues ({len(survivors)}):")
        for number in survivors:
            print(f"  #{number}")
    else:
        print(f"unclaimed: 0 of {len(open_numbers)} open issues")

    # Drift, both directions. A label the plan does not justify is as much a
    # defect as a missing one - it is what makes `gh issue list --label
    # phase:N` disagree with the plan nobody re-read.
    missing: list[str] = []
    extra: list[str] = []
    for number in sorted(plan.scheduled):
        issue = issues.get(number)
        if issue is None:
            missing.append(f"#{number} is scheduled but does not exist")
            continue
        want = plan.label_for(number)
        have = _phase_labels(issue)
        if want not in have:
            missing.append(
                f"#{number} should carry {want}, has {sorted(have) or 'none'}"
            )
        for name in sorted(have - {want}):
            extra.append(f"#{number} carries {name} but the plan puts it in {want}")
    for number, issue in sorted(issues.items()):
        if number in plan.scheduled:
            continue
        for name in sorted(_phase_labels(issue)):
            extra.append(f"#{number} carries {name} but the plan schedules it nowhere")

    if missing or extra:
        rc = 1
        print(f"::error::phase-label drift ({len(missing) + len(extra)}):")
        for line in missing + extra:
            print(f"  {line}")
        print("\nRe-run `python scripts/dev/phase_audit.py labels --apply`.")
    else:
        print(f"labels: {len(plan.scheduled)} scheduled issues all carry their phase")

    return rc


def cmd_closers(plan: PlanIndex, rev_range: str, ref: str, check: bool) -> int:
    """Issues fixed on `dev` whose closing keyword must reach `main`.

    "Fixed" is derived, not asserted: an issue counts if its phase's squash
    commit is on `dev` and the issue is still OPEN. Phase 0's issues drop out
    on the second condition, which is what the old raw-count query got wrong in
    the other direction.
    """
    landed = landed_phases(ref)
    issues = fetch_issues()
    have = keywords_in_range(rev_range)

    expected: list[int] = []
    for phase in sorted(landed):
        for number in plan.phases.get(phase, []):
            issue = issues.get(number)
            if issue is not None and issue.state == "OPEN":
                expected.append(number)

    missing = [n for n in expected if n not in have]
    covered = [n for n in expected if n in have]

    print(f"landed phases on {ref}: {sorted(landed)}")
    print(f"keyword range       : {rev_range}  ({len(have)} distinct issues named)")
    print(f"fixed-but-open      : {len(expected)}  {_fmt(expected)}")
    print(f"  covered by a keyword: {len(covered)}  {_fmt(covered)}")
    print(f"  MISSING             : {len(missing)}  {_fmt(missing)}")

    # The second population, which the phase rosters structurally cannot reach.
    # Run unconditionally rather than behind a flag: the whole finding is that
    # the bookkeeping looked done and was not, and a sweep nobody remembers to
    # ask for is the same failure with an extra step.
    inert = inert_closers(fetch_merged_prs(), issues)
    print(f"inert keywords      : {len(inert)} merged PR(s) named an open issue")
    for pr, gap in inert:
        print(f"  PR #{pr.number} (base {pr.base}, {pr.merged_at}) -> {_fmt(gap)}")

    if not missing and not inert:
        print(
            "\nevery issue fixed on dev carries a closing keyword in range, and "
            "no merged PR named an open issue GitHub did not link"
        )
        return 0

    if missing:
        print(
            f"\n{len(missing)} issue(s) are fixed on {ref} with no closing "
            "keyword in its history, so the sync will not close them. Put these "
            "in an individual COMMIT message, one `Closes #N` each. A PR body "
            "targeting `dev` is inert - GitHub records no closing reference for "
            "a PR whose base is not the default branch."
        )
    if inert:
        print(
            f"\n{len(inert)} merged PR(s) name an OPEN issue with a closing "
            "keyword GitHub never recorded, so those issues are fixed and "
            "nothing will close them. Carry the keywords on a bookkeeping "
            "commit, the way #1000's eleven were."
        )
    if not check:
        return 0
    print(
        f"\n::error::{len(missing)} unclosed fixed issue(s) and {len(inert)} "
        f"PR(s) with an inert keyword. Neither will close at the sync."
    )
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    sub = parser.add_subparsers(dest="command", required=True)
    p_derive = sub.add_parser("derive", help="parse the plan; no network")
    p_derive.add_argument("--json", action="store_true", dest="as_json")
    p_labels = sub.add_parser("labels", help="create and apply phase:N labels")
    p_labels.add_argument("--apply", action="store_true")
    sub.add_parser("unclaimed", help="open issues the plan does not mention")
    sub.add_parser("verify", help="unclaimed + label drift; the CI gate")
    p_closers = sub.add_parser(
        "closers", help="issues fixed on dev whose closing keyword must reach main"
    )
    p_closers.add_argument(
        "--range", dest="rev_range", default="origin/main..origin/dev"
    )
    p_closers.add_argument("--ref", default="origin/dev")
    p_closers.add_argument("--check", action="store_true", help="exit 1 if any missing")
    args = parser.parse_args(argv)

    try:
        plan = load_plan(args.plan)
    except PlanParseError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 2

    if args.command == "derive":
        return cmd_derive(plan, args.as_json)
    if args.command == "labels":
        return cmd_labels(plan, args.apply)
    if args.command == "unclaimed":
        return cmd_unclaimed(plan)
    if args.command == "closers":
        return cmd_closers(plan, args.rev_range, args.ref, args.check)
    return cmd_verify(plan)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
