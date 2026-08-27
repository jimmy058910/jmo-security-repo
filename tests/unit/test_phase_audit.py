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
    PlanParseError,
    closing_keywords,
    load_plan,
    parse_plan,
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
