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

import json
from pathlib import Path

import pytest

from scripts.dev import phase_audit
from scripts.dev.phase_audit import (
    DEFAULT_PLAN,
    Issue,
    MergedPR,
    PlanParseError,
    closing_keywords,
    cmd_labels,
    cmd_unclaimed,
    cmd_verify,
    inert_closers,
    load_plan,
    parse_plan,
    phases_in_subjects,
    tracked_tools,
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
    ), (
        "a phase with no roster must fail as a missing roster, not absorb the next section's"
    )


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


# --------------------------------------------------------------------------
# `labels --apply` must be the inverse of `verify`
#
# `verify` flags drift in both directions and ends with "Re-run `labels
# --apply`". That is only true if `labels` also removes a `phase:N` label from
# an issue the plan schedules NOWHERE. Measured 2026-09-12 while seating the
# v2.0.0 plan: `verify` reported 137 such labels - every one on a closed
# v1.1.0 issue - and `labels --apply` proposed 0 removals, because it walked
# only the plan's own rosters. A plan switch left the previous program's
# labels in place and the gate red, with no command that could green it.
# --------------------------------------------------------------------------


def _labels_world(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, ...]]:
    """One plan, five issues, and a `gh` that records instead of writing."""
    issues = {
        # scheduled in Phase 0, unlabelled: the add the command always did
        100: Issue(number=100, state="OPEN", labels=set()),
        # scheduled in Phase 0 with a stale extra: the removal it always did
        101: Issue(number=101, state="OPEN", labels={"phase:0", "phase:7"}),
        # after the tag, still carrying a label from the previous program
        900: Issue(number=900, state="OPEN", labels={"phase:9"}),
        # closed under the previous program: the 137-issue population
        555: Issue(number=555, state="CLOSED", labels={"phase:3", "bug"}),
        # nothing to do, and a control that the sweep touches only phase labels
        777: Issue(number=777, state="CLOSED", labels={"bug"}),
    }
    calls: list[tuple[str, ...]] = []

    def fake_gh(*args: str) -> str:
        calls.append(args)
        if args[:2] == ("label", "list"):
            return json.dumps([{"name": f"phase:{n}"} for n in range(11)])
        return ""

    monkeypatch.setattr(phase_audit, "fetch_issues", lambda *a, **k: issues)
    monkeypatch.setattr(phase_audit, "_gh", fake_gh)
    return calls


def test_labels_apply_removes_labels_the_plan_schedules_nowhere(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls = _labels_world(monkeypatch)
    plan = parse_plan(BASE, Path("plan.md"))

    assert cmd_labels(plan, apply=True) == 0

    edits = {c for c in calls if c[:2] == ("issue", "edit")}
    assert ("issue", "edit", "100", "--add-label", "phase:0") in edits
    assert ("issue", "edit", "101", "--remove-label", "phase:7") in edits
    # The two the old loop could not reach: unscheduled, open and closed.
    assert ("issue", "edit", "900", "--remove-label", "phase:9") in edits
    assert ("issue", "edit", "555", "--remove-label", "phase:3") in edits
    # Only `phase:` labels are the plan's to remove.
    assert not any("bug" in c for c in edits)
    assert not any(c[2] == "777" for c in edits)
    assert "applied: 1 label(s) added, 3 removed, 0 created" in capsys.readouterr().out


def test_labels_dry_run_reports_the_sweep_and_writes_nothing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls = _labels_world(monkeypatch)
    plan = parse_plan(BASE, Path("plan.md"))

    assert cmd_labels(plan, apply=False) == 0

    assert not any(c[:2] == ("issue", "edit") for c in calls)
    out = capsys.readouterr().out
    assert "~ #555 drop phase:3" in out
    assert "~ #900 drop phase:9" in out
    assert "would apply: 1 label(s) added, 3 removed, 0 created" in out


# --------------------------------------------------------------------------
# Version-checker issues are exempt only while something will close them
#
# `update_versions.py --create-issues` (weekly, maintenance.yml) files
# `Update <tool> to v<x>` and closes its predecessor when it files the next.
# Counting those as unclaimed kept `verify` red on every open PR: measured
# 2026-09-23, 4 of the 5 unclaimed issues were these, and the weekly
# maintenance routine had auto-merged nothing since 2026-08-31 because no PR
# could reach CLEAN. The exemption holds only while `versions.yaml` still
# lists the tool, because that is the only condition under which the checker
# will ever close the issue. A tool the program removes loses the exemption,
# which is what makes its removal PR close the issue instead of orphaning it.
# --------------------------------------------------------------------------

BOT = "app/github-actions"

# The real file's shapes, including the two that defeat a naive scan: a list
# of dicts under `version_history` and a bare `  critical_tools:` key under
# `update_policies`, both indented exactly like a tool name.
VERSIONS_YAML = """\
schema_version: '1.0'
python_tools:
  ruff:
    version: 0.16.5
    pypi_package: ruff
binary_tools:
  grype:
    version: 0.118.0
    update_check: docker inspect x | jq -r
      '.[0].Created'
special_tools:
  semgrep:
    version: 1.175.0
docker_images:
  ubuntu:
    version: '24.04'
update_policies:
  critical_tools:
    tools:
    - trivy
version_history:
- date: '2026-09-09'
  action: Updated falcoctl
  tools_updated:
  - tool: falcoctl
    old_version: 0.13.0
"""


def test_tracked_tools_reads_only_the_sections_the_checker_walks() -> None:
    assert tracked_tools(VERSIONS_YAML) == {"ruff", "grype", "semgrep"}


def test_tracked_tools_agrees_with_a_real_yaml_parse_of_the_real_file() -> None:
    """The stdlib scan is a guess about formatting; yaml is the authority.

    `phase_audit.py` is stdlib-only so its CI job needs no `uv sync`, which is
    why it cannot just call `yaml.safe_load`. This test can, so it is what
    catches a `versions.yaml` reformat that the scan would silently misread.
    """
    yaml = pytest.importorskip("yaml")
    path = phase_audit.VERSIONS_YAML
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    expected = {
        tool
        for section in phase_audit.CHECKED_SECTIONS
        for tool in (data.get(section) or {})
    }

    found = tracked_tools(path.read_text(encoding="utf-8"))

    assert found == expected
    # An extractor that finds nothing agrees with an empty parse; the floor
    # and a named member are what stop that from passing.
    assert len(found) >= 10
    assert "ruff" in found


def _unclaimed_world(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, extra: Issue
) -> None:
    """BASE's plan with every scheduled issue correctly labelled, plus one."""
    versions = tmp_path / "versions.yaml"
    versions.write_bytes(VERSIONS_YAML.encode("utf-8"))
    monkeypatch.setattr(phase_audit, "VERSIONS_YAML", versions)
    issues = {n: Issue(number=n, state="OPEN", labels={"phase:0"}) for n in (100, 101)}
    issues.update(
        {n: Issue(number=n, state="OPEN", labels={"phase:1"}) for n in (200, 201, 202)}
    )
    issues.update({n: Issue(number=n, state="OPEN") for n in (900, 901)})
    issues[extra.number] = extra
    monkeypatch.setattr(phase_audit, "fetch_issues", lambda *a, **k: issues)


@pytest.mark.parametrize(
    "title",
    ["Update ruff to v0.16.8", "[CRITICAL] Update semgrep to v1.176.0"],
    ids=["normal", "critical"],
)
def test_a_version_issue_for_a_tracked_tool_is_exempt_and_says_so(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    title: str,
) -> None:
    issue = Issue(
        number=300, state="OPEN", labels={"dependencies"}, author=BOT, title=title
    )
    _unclaimed_world(monkeypatch, tmp_path, issue)
    # Under the repo root: the unclaimed message prints the plan path relative to it.
    plan = parse_plan(BASE, phase_audit.REPO_ROOT / "plan.md")

    assert cmd_unclaimed(plan) == 0
    assert cmd_verify(plan) == 0
    # Exempt is not invisible: both commands name what they let through.
    out = capsys.readouterr().out
    assert out.count("exempt") >= 2
    assert "#300" in out


@pytest.mark.parametrize(
    ("author", "labels", "title"),
    [
        # Removed from versions.yaml: the checker never looks at it again.
        (BOT, {"dependencies"}, "Update falcoctl to v0.14.2"),
        # Same bot, no close mechanism at all.
        (BOT, {"bug", "ci", "nightly-test-failure"}, "Nightly test suite failed"),
        # A person asking for the bump is a decision, not churn.
        ("jimmy058910", {"dependencies"}, "Update ruff to v0.16.8"),
        # The checker's sweep queries `--label dependencies`; without it, the
        # issue is invisible to the thing that would close it.
        (BOT, set(), "Update ruff to v0.16.8"),
    ],
    ids=["removed-tool", "nightly-failure", "human-filed", "unlabelled"],
)
def test_an_issue_nothing_will_close_stays_unclaimed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    author: str,
    labels: set[str],
    title: str,
) -> None:
    issue = Issue(number=301, state="OPEN", labels=labels, author=author, title=title)
    _unclaimed_world(monkeypatch, tmp_path, issue)
    # Under the repo root: the unclaimed message prints the plan path relative to it.
    plan = parse_plan(BASE, phase_audit.REPO_ROOT / "plan.md")

    assert cmd_unclaimed(plan) == 1
    assert cmd_verify(plan) == 1
    assert "#301" in capsys.readouterr().out
