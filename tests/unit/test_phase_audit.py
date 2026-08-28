#!/usr/bin/env python3
"""Tests for `scripts/dev/phase_audit.py`.

The parser answers "is this issue scheduled?" by reading the fix-program plan.
Everything downstream - the phase labels, the CI gate, the sync's closing
keywords - is derived from that answer, so a parser that quietly finds *some*
issues is worse than one that crashes: it produces a plausible mapping nobody
re-checks.

So the tests worth having are the ones that prove the parser's own checksums
fire. Each `test_rejects_*` below is a negative control: it mutates exactly one
number and asserts the parse fails *for that reason*. `test_tolerates_*` are the
positive controls - the reflows the parser claims to survive, which is what
stops the checksums from being satisfied by a parser that rejects everything.

`test_real_plan_parses` is the load-bearing one. It is what turns this from a
session measurement into a gate: any future edit that desynchronises a roster
from its declared count, its summary-table row, or the total reddens CI.
"""

from __future__ import annotations

import pytest

from scripts.dev.phase_audit import (
    DEFAULT_PLAN,
    Issue,
    MergedPR,
    PlanParseError,
    closing_keywords,
    inert_closers,
    load_plan,
    parse_plan,
    phases_in_subjects,
)

# The plan separates a summary row's phase number from its name with an EM DASH
# (U+2014), and the row regex requires it. Spelled as an escape so this file
# stays pure ASCII: a literal would be re-encoded by any tool that rewrites the
# file, and would raise UnicodeEncodeError if a failure message reached a
# cp1252 console - the exact class of bug this repo keeps re-finding.
DASH = "\u2014"

BASE = f"""# Test plan

## Phase 0 {DASH} Instruments

**2 issues:**
`#100 #101`

Prose about phase 0 that mentions no issues.

## Phase 1 {DASH} Gates

**3 issues:** #200 #201 #202

## After the tag

**2 issues, deliberately not phase work.** ROADMAP features
`#900 #901`.

## Phase summary

| Phase | n | Gate it protects | State |
|---|---:|---|---|
| 0 {DASH} instruments | 2 | every later measurement | **DONE** |
| 1 {DASH} gates | 3 | {DASH} | |
| **before tag** | **5** | | |
| after tag | 2 | not phase work | |
"""


def mutate(old: str, new: str, text: str = BASE) -> str:
    """Replace `old` once, asserting the mutation actually applied.

    A negative control that silently fails to mutate is indistinguishable from
    a gate that works. Two of the mutation tests written for Phase 1 no-opped
    for exactly this reason, so the assertion is the point of the helper.
    """
    assert text.count(old) == 1, f"anchor {old!r} appears {text.count(old)} times"
    mutated = text.replace(old, new)
    assert mutated != text, "mutation did not apply"
    return mutated


# --------------------------------------------------------------------------
# The happy path
# --------------------------------------------------------------------------


def test_parses_all_three_roster_shapes() -> None:
    """Marker-then-next-line, marker-and-list-on-one-line, and the after-tag list."""
    plan = parse_plan(BASE)
    assert plan.phases == {0: [100, 101], 1: [200, 201, 202]}
    assert plan.after_tag == [900, 901]
    assert plan.summary_total == 5
    assert plan.summary_after_tag == 2


def test_scheduled_and_all_known_are_distinct_sets() -> None:
    """`unclaimed` subtracts `all_known`; `verify` labels only `scheduled`.

    Conflating them would either label the after-tag issues (wrong - they are
    not phase work) or report them as unclaimed (wrong - the plan names them).
    """
    plan = parse_plan(BASE)
    assert plan.scheduled == {100, 101, 200, 201, 202}
    assert plan.all_known == {100, 101, 200, 201, 202, 900, 901}


def test_phase_and_label_lookup() -> None:
    plan = parse_plan(BASE)
    assert plan.phase_of(201) == 1
    assert plan.label_for(201) == "phase:1"
    assert plan.phase_of(900) is None, "an after-tag issue is in no phase"
    assert plan.label_for(900) is None


# --------------------------------------------------------------------------
# Negative controls - one mutation each, asserted to fire for its own reason
# --------------------------------------------------------------------------


def test_rejects_issue_dropped_from_roster() -> None:
    """Checksum 1: the roster's own `**N issues:**` prefix."""
    with pytest.raises(PlanParseError) as err:
        parse_plan(mutate("#200 #201 #202", "#200 #201"))
    assert "roster says `**3 issues**` but 2 were parsed" in str(err.value)


def test_rejects_declared_count_alone() -> None:
    """Checksum 1 again, mutated from the other side.

    Dropping an issue and inflating the count are the same arithmetic but
    different edits; a parser that recomputed the count from the roster would
    pass this one.
    """
    with pytest.raises(PlanParseError) as err:
        parse_plan(mutate("**3 issues:**", "**4 issues:**"))
    assert "roster says `**4 issues**` but 3 were parsed" in str(err.value)


def test_rejects_summary_row_disagreeing_with_roster() -> None:
    """Checksum 2: the per-phase `n` column, which is written by hand."""
    with pytest.raises(PlanParseError) as err:
        parse_plan(mutate(f"| 1 {DASH} gates | 3 |", f"| 1 {DASH} gates | 4 |"))
    assert "Phase 1: summary table says 4, roster has 3" in str(err.value)


def test_rejects_total_disagreeing_with_sum() -> None:
    """Checksum 3: the `before tag` total."""
    with pytest.raises(PlanParseError) as err:
        parse_plan(mutate("| **before tag** | **5** |", "| **before tag** | **6** |"))
    assert "`before tag` says 6, the phase rosters sum to 5" in str(err.value)


def test_rejects_issue_scheduled_in_two_phases() -> None:
    """Checksum 4.

    Reported as itself rather than as an arithmetic error, because "#N is in
    two phases" and "a count is off by one" need different fixes.
    """
    with pytest.raises(PlanParseError) as err:
        parse_plan(
            mutate(
                "**3 issues:** #200 #201 #202",
                "**4 issues:** #200 #201 #202 #100",
            ).replace(f"| 1 {DASH} gates | 3 |", f"| 1 {DASH} gates | 4 |")
        )
    assert "#100 is in both Phase 0 and Phase 1" in str(err.value)


def test_rejects_missing_roster() -> None:
    """A phase section with no roster at all is a parse failure, not zero issues.

    Treating it as zero is the shape that lets a whole phase go unlabelled
    while every count still adds up.
    """
    with pytest.raises(PlanParseError) as err:
        parse_plan(mutate("**3 issues:** #200 #201 #202\n\n", ""))
    assert "no `**N issues:**` roster found in the section starting at line" in str(
        err.value
    ), "a phase with no roster must fail as a missing roster, not absorb the next section's"


def test_rejects_summary_row_for_a_phase_that_does_not_exist() -> None:
    """Drift in the other direction: a table row outliving its section."""
    with pytest.raises(PlanParseError) as err:
        parse_plan(
            mutate(
                "| after tag | 2 |",
                f"| 2 {DASH} ghost | 0 |\n| after tag | 2 |",
            )
        )
    assert "row for Phase 2 with no `## Phase 2` section" in str(err.value)


def test_rejects_after_tag_count_drift() -> None:
    with pytest.raises(PlanParseError) as err:
        parse_plan(mutate("| after tag | 2 |", "| after tag | 3 |"))
    assert "After the tag: summary table says 3, roster has 2" in str(err.value)


def test_rejects_stray_reference_inside_a_roster() -> None:
    """A `#997` PR reference in a roster paragraph would be read as an issue.

    The parser cannot tell them apart - the declared count is what catches it,
    which is why the count is checked rather than trusted.
    """
    with pytest.raises(PlanParseError) as err:
        parse_plan(
            mutate(
                "**2 issues:**\n`#100 #101`", "**2 issues:**\n`#100 #101` (see PR #997)"
            )
        )
    assert "3 were parsed: #100 #101 #997" in str(err.value)


# --------------------------------------------------------------------------
# Positive controls - the reflows the parser claims to survive
# --------------------------------------------------------------------------


def test_tolerates_a_roster_rewrapped_across_lines() -> None:
    plan = parse_plan(
        mutate("**3 issues:** #200 #201 #202", "**3 issues:** #200\n#201 #202")
    )
    assert plan.phases[1] == [200, 201, 202]


def test_tolerates_a_roster_with_a_qualifier_in_its_marker() -> None:
    """`**6 issues, in this order:**` is how Phase 4 is written."""
    plan = parse_plan(mutate("**3 issues:**", "**3 issues, in this order:**"))
    assert plan.phases[1] == [200, 201, 202]


def test_tolerates_grouping_punctuation_between_issues() -> None:
    """Phase 4 separates with arrows, Phase 6 with parenthesised group names."""
    plan = parse_plan(
        mutate(
            "**3 issues:** #200 #201 #202",
            "**3 issues:** cli (#200 #201) " + "\u00b7" + " mcp (**#202**)",
        )
    )
    assert plan.phases[1] == [200, 201, 202]


# --------------------------------------------------------------------------
# The gate
# --------------------------------------------------------------------------


def test_real_plan_parses() -> None:
    """The fix-program plan agrees with itself.

    This is the gate. It needs no network and no labels: it fails the moment a
    plan edit desynchronises a roster from its declared count, its
    summary-table row, or the `before tag` total.
    """
    plan = load_plan(DEFAULT_PLAN)
    derived = sum(len(v) for v in plan.phases.values())
    assert derived == plan.summary_total
    assert len(plan.after_tag) == plan.summary_after_tag
    assert plan.scheduled.isdisjoint(plan.after_tag)
    assert sorted(plan.phases) == list(range(len(plan.phases))), (
        "phase numbers must be contiguous from 0; a gap means a section was "
        "renamed or lost"
    )


# --------------------------------------------------------------------------
# Closing keywords - what GitHub would actually act on
# --------------------------------------------------------------------------


def test_recognises_the_forms_github_accepts() -> None:
    assert closing_keywords("Closes #960") == {960}
    assert closing_keywords("fixes #12") == {12}
    assert closing_keywords("Resolved: #3") == {3}
    assert closing_keywords("fix\t#7") == {7}


def test_is_case_insensitive() -> None:
    """A `grep -oE 'closes #'` misses a capitalised `Closes #538`; #538 was."""
    assert closing_keywords("CLOSES #538\nclosed #539") == {538, 539}


def test_does_not_bridge_a_sentence_break() -> None:
    r"""The false positive this regex was tightened to reject.

    `1d8a916` contains "...and those are what this fixes.\n\n#976 item 1 ...".
    A separator of `\s*` or `[^\w#]{0,4}` reads that as closing #976, so the
    check reported an issue as covered when nothing would close it - a false
    NEGATIVE in the gate, which is the direction that ships the bug.
    """
    body = "...and those are what this fixes.\n\n#976 item 1 is DISMISSED"
    assert closing_keywords(body) == set()


def test_does_not_span_a_line_break() -> None:
    """GitHub does not close on a keyword whose reference is on the next line."""
    assert closing_keywords("Closes\n#42") == set()


def test_a_bare_reference_closes_nothing() -> None:
    """The lesson chunk 22 already paid for: `#N` alone is a cross-link."""
    assert closing_keywords("See #785 for context, related to #999") == set()


def test_finds_every_keyword_in_a_multi_issue_body() -> None:
    """A bookkeeping commit carries one line per issue; all of them must count."""
    body = "\n".join(f"Closes #{n}" for n in (960, 962, 961, 922, 756))
    assert closing_keywords(body) == {960, 962, 961, 922, 756}


# --------------------------------------------------------------------------
# Which commit subjects count as a phase having landed
#
# `landed_phases` decides the population `closers --check` gates on. A phase it
# fails to recognise silently drops that phase's open issues from the check, so
# the gate reports `MISSING: 0` over issues that will sync to `main` still open
# - the exact failure it exists to prevent. Subjects below are real, taken from
# `git log origin/dev --format=%s`.
# --------------------------------------------------------------------------


LANDED_SUBJECTS = [
    f"Phase 8 {DASH} claims and documentation (#1045)",
    f"fix(dashboard): Phase 7 {DASH} ship the built dashboard (#1033)",
    f"fix: Phase 6 {DASH} subsystems (schedule, MCP, attest) (#1022)",
    f"Phase 5 {DASH} the command surface (14 issues) (#1013)",
]

MENTION_ONLY_SUBJECTS = [
    # Bookkeeping commits: they name a phase and land nothing.
    "docs(plan): schedule #1047 and #1048 into Phase 9 (#1049)",
    "docs(plan): record Phase 7's merge SHA (#1034)",
    f"merge: sync dev -> main (Phases 1, 2 and 2.5) {DASH} no release (#1002)",
    # 2.5 is not a numbered phase in the plan, and `2.` is not `2 {DASH}`.
    f"Phase 2.5 {DASH} instruments for the fix program's own tracking (#1001)",
    # Predate the fix program: `Phase N` here is some feature's own phase N.
    "feat(history): Phase 9 complete - SQLite storage 100% production-ready",
    "refactor(wizard): complete Phase 5 cleanup and documentation (Final)",
    # These three are the ones an unanchored regex actually misreads - measured
    # across all 1165 subjects in this repository, they are the only ones.
    "feat(dedup): complete cross-tool deduplication (Phase 0-9)",
    "feat(dedup): implement cross-tool deduplication (Phase 0-7)",
    "feat(wizard): implement Feature #4 Phase 1 - Enhanced workflows",
]

REAL_SUBJECTS = "\n".join(LANDED_SUBJECTS + MENTION_ONLY_SUBJECTS)


def test_recognises_a_squash_behind_a_conventional_commit_prefix() -> None:
    """The defect. Phases 6 and 7 squashed with a `fix:` / `fix(scope):` prefix.

    A bare `^Phase` anchor reported `[0, 1, 2, 3, 4, 5, 8]` on `origin/dev`.
    It gave the right answer only because every Phase 6 and 7 issue happened to
    be closed by then; one of them without a closing keyword would have synced
    still open, behind a green gate.
    """
    assert phases_in_subjects(REAL_SUBJECTS) == {5, 6, 7, 8}


def test_a_subject_that_merely_mentions_a_phase_has_not_landed_it() -> None:
    """Why the conventional-commit prefix is ANCHORED and not skipped over.

    Each subject is asserted ALONE, and that is the point. Asserting against
    the union hides a false positive whenever a true positive contributes the
    same number: dropping the `^` makes `(Phase 0-9)` report phase 0 and
    `Feature #4 Phase 1 - Enhanced workflows` report phase 1, but phases 0 and
    1 really did land, so the aggregate set is unchanged and the mutation
    survives. The first version of this test asserted the union and did exactly
    that.
    """
    for subject in MENTION_ONLY_SUBJECTS:
        assert phases_in_subjects(subject) == set(), subject


def test_a_bare_phase_subject_is_still_recognised() -> None:
    """The other control: the original unprefixed form must keep working."""
    assert phases_in_subjects(f"Phase 0 {DASH} instruments (17 issues) (#978)") == {0}


def test_a_hyphen_separator_is_accepted_but_a_word_is_not() -> None:
    """`[—-]` is the separator set; `Phase 9 complete` is prose, not a landing."""
    assert phases_in_subjects("Phase 3 - one-liners") == {3}
    assert phases_in_subjects("Phase 3 complete - one-liners") == set()


# --------------------------------------------------------------------------
# The second population: keywords GitHub never recorded
#
# `closers` derives "fixed" from "this issue's phase landed", so anything fixed
# before the phase program existed is outside it. That window - the 22-chunk
# campaign - is where inert keywords are most likely, because every chunk PR
# was based on `dev`.
# --------------------------------------------------------------------------


def _issue_map(states: dict[int, str]) -> dict[int, Issue]:
    return {n: Issue(number=n, state=s) for n, s in states.items()}


def test_flags_a_keyword_github_never_recorded() -> None:
    """PR #793's shape: five keywords in the body, zero closing references.

    `a45e5b4` fixed #787 through #791 on 2026-08-09 through a PR based on
    `dev`, so GitHub recorded nothing, and all five sat open for seventeen days
    while `closers --check` printed `MISSING: 0`.
    """
    pr = MergedPR(
        number=793,
        base="dev",
        merged_at="2026-08-09",
        named={787, 788, 789, 790, 791},
        linked=set(),
    )
    issues = _issue_map(dict.fromkeys((787, 788, 789, 790, 791), "OPEN"))
    assert inert_closers([pr], issues) == [(pr, [787, 788, 789, 790, 791])]


def test_ignores_a_keyword_that_names_a_pull_request() -> None:
    """Six merged PRs here say `Closes #N` about another PULL REQUEST.

    GitHub correctly records no closing reference for those, so a bare
    `named - linked` gap reports all six as defects. `gh issue list` does not
    return PRs, so absence from the issue map discriminates them without a
    special case - PR #96's body literally reads "Merges PR #95 ... Closes #95".
    """
    pr = MergedPR(
        number=96, base="main", merged_at="2025-10-27", named={95}, linked=set()
    )
    assert inert_closers([pr], _issue_map({})) == []


def test_ignores_an_issue_that_is_already_closed() -> None:
    """The population is what still needs action, not what once did.

    #1000's eleven have this shape now: named by PR #995 / #997, never linked,
    and closed since by a bookkeeping commit.
    """
    pr = MergedPR(
        number=995, base="dev", merged_at="2026-08-26", named={960}, linked=set()
    )
    assert inert_closers([pr], _issue_map({960: "CLOSED"})) == []


def test_catches_a_pr_that_linked_only_some_of_what_it_named() -> None:
    """Why the discriminator is `named - linked` and not `base != main`.

    A base-branch test sees this PR as fine, because its base IS the default
    branch. Only comparing the two sets finds the one issue that will not
    close.
    """
    pr = MergedPR(
        number=1,
        base="main",
        merged_at="2026-01-01",
        named={10, 11, 12},
        linked={10, 12},
    )
    issues = _issue_map({10: "CLOSED", 11: "OPEN", 12: "CLOSED"})
    assert inert_closers([pr], issues) == [(pr, [11])]


def test_a_fully_linked_pr_is_not_flagged() -> None:
    """The control. PR #986's shape: base `main`, every keyword recorded."""
    pr = MergedPR(
        number=986,
        base="main",
        merged_at="2026-08-25",
        named={10, 11},
        linked={10, 11},
    )
    assert inert_closers([pr], _issue_map({10: "OPEN", 11: "OPEN"})) == []
