# GitHub-native issue planning: design

**Date:** 2026-10-31 · **Status:** draft for maintainer approval (open questions settled 2026-10-31) · **Repo:** `jimmy058910/jmo-security-repo` (user-owned, public)

## 1. Intent

The maintainer's working loop is: ask the agent "what should we work on next?", get a
top 3, pick one. Today the agent assembles that answer by reading three things that can
disagree: the program plan's issue rosters, the `phase:N` labels, and the rolling handoff.
`scripts/dev/phase_audit.py` (967 lines) exists mainly to catch the first two drifting
apart, and the session-end routine carries several rules whose only purpose is to keep
the plan's rosters, counts and labels consistent across open PRs.

This design makes **GitHub Issues the single source of truth** for what is open, how
important it is, what it waits on, and what blocks it, so the top 3 is computed from
GitHub state by one script. The plan documents keep the *why* (measurements, decisions,
task detail) and stop carrying issue rosters.

Two things the current setup cannot represent become first-class:

- **Pending decisions.** A question only the maintainer can answer currently lives in a
  handoff file outside the repo. It becomes a labelled issue with a fixed body template.
- **Blockers.** Ordering such as "PR G and PR Y precede PR F" lives in plan prose. It
  becomes native GitHub "blocked by" links that the script reads.

## 2. Goals, non-goals, anti-goals

**Goals**

1. One store: every fact the ranking needs lives on the issue (labels, links, state).
2. A script prints the top 3 ready items, the decisions waiting on the maintainer, the
   blocker whose closure frees the most work, and how many issues are untriaged.
3. The agent can read and write all of it with `gh` and the existing token
   (`repo` scope). No new service, binary, or token scope.
4. The agent proposes, the maintainer confirms: no priority is applied without the
   maintainer's agreement.
5. The session-start skill shows the ranking; the session-end skill files new issues
   with priority, phase and links already set.
6. `phase-audit` ends up checking GitHub hygiene instead of plan-versus-label agreement.

**Non-goals**

- Moving the repo to an organization (decided 2026-10-31; see §9 for the later path).
- GitHub Projects boards, milestones, or any third-party planner (Linear, ZenHub, Plane,
  Backlog.md, Beads; all evaluated and rejected, §10).
- Changing the weekly unattended maintenance routine. It does not rank or prioritise.
- Automatic prioritisation by the agent.

**Anti-goals** (failure even if it technically works)

- A second copy of any fact. If the same thing is stated in two places, one will drift.
- The agent applying priorities on its own judgement.
- Private information in public issue text (machine names, private repo names, internal
  hosts). Issues on this repo are public.
- Turning `phase-audit` red for contributors or for unrelated open PRs during rollout.

## 3. Constraints (measured 2026-10-31)

- **User-owned repo.** Issue types and issue fields (typed Priority) are organization-only;
  `repository.issueTypes` is `null` here and `viewerCanSetFields` is `false`.
- **Available and tested on this repo or a throwaway twin:** labels, sub-issues
  (GA 2025-04-09; 100 children, 8 levels, one parent per issue), issue dependencies
  (GA 2025-08-21; 50 links per type), and label *suggestions* (below).
- **`gh` 2.94.0 or later** for `--parent`, `--add-sub-issue`, `--add-blocked-by`,
  `--add-blocking` and the `parent`, `subIssues`, `blockedBy`, `blocking` JSON fields.
  The maintainer's machine has 2.103.0. Debian's packaged 2.46.0 lacks all of them.
- **Measured semantics** (throwaway repo, 2026-10-31):
  - `is:blocked`, `is:blocking`, `-is:blocked`, `has:sub-issue`, `has:parent-issue`,
    `no:parent-issue` work in `gh issue list --search`.
  - `blocked-by:N`, `blocking:N` and `parent-issue:...` return nothing via `gh` search in
    every spelling tried. Read relationships from JSON, not search.
  - Closing a blocker unblocks the dependent within about 10 s. The link remains, shown
    as `CLOSED`; REST `issue_dependencies_summary.blocked_by` counts **open** blockers only.
  - **A blocked parent does not block its sub-issues.** Propagation is the script's job.
  - Every relationship change is a timeline event with actor and time
    (`blocked_by_added`, `sub_issue_added`, label events).
  - One REST call, `GET /repos/{owner}/{repo}/issues?state=open&per_page=100` (paginated),
    returns labels, `issue_dependencies_summary`, `sub_issues_summary` and
    `parent_issue_url` for every issue (0.57 s on a small repo).
  - **Label suggestions work on a user-owned repo:** `updateIssue` with
    `labels: [{labelId, suggest: true, rationale, confidence}]` stores a
    `PendingLabelSuggestion` with its rationale; the label is not applied until accepted
    (`applyPendingIssueSuggestions`, kind `LABEL`).
- **Repo state:** 105 open issues, 104 authored by the maintainer, 1 bot-filed (a weekly
  `Update <tool> to vX` issue). 70 carry a `phase:N` label, 35 do not, 9 carry
  `disposition:DEFER-POST-1.1.0`. No sub-issues, dependencies, milestones or assignees in use.
- **`phase-audit`** is a CI job on `pull_request`, skipped on forks, and **not** a required
  check in either branch ruleset. Its `verify` fails (exit 1) on an open issue the plan does
  not roster ("unclaimed", except weekly version-checker issues) **and** on a `phase:N`
  label the plan does not back ("label drift"); `labels --apply` strips such labels. The
  weekly maintenance routine reads this job's conclusion before auto-merging. A PR into
  `main` (Dependabot security PRs) runs `main`'s copy of the audit.
- **Closing.** PRs target `dev`, whose PR-body keywords are inert because `main` is the
  default branch. Closing keywords go in squash commit messages, so issues close only when
  `dev` is synced to `main`. `closers --check` verifies this, for rostered issues only.
- **REST `issue_dependencies_summary`** gives counts, not link targets. Edges with their
  state come from `gh issue list --json blockedBy,blocking` (measured: all 105 open issues
  with every ranking field in 1.1 s).
- **Session skills** (`/start`, `/done`) are maintainer-local and untracked, each capped
  at 500 body lines by its own self-check; `/done` is at the cap, so additions must
  replace text.

## 4. The convention (decided)

Labels use the repo's existing `axis:value` style (`phase:6`). Each label's GitHub
description carries its definition, so the definition is visible wherever the label is.

| Question | Mechanism | Definition (goes in the label description) |
|---|---|---|
| How much does it matter? | `priority:p1` | Someone would notice in the release: a user-reachable defect, a security or data-integrity flaw, a red gate, or a prerequisite for the active phase's exit. Work before any p2. Soft cap: about 7 open. |
| | `priority:p2` | Planned and wanted; waiting harms nobody. The normal state of phase work. |
| | `priority:p3` | Accepted, parked on purpose. Replaces `disposition:DEFER-POST-1.1.0`. Close as not planned if still p3 after two phases close. |
| | *(no priority label)* | Untriaged. Never ranked; counted every session until triaged. |
| Waiting on the maintainer? | `needs:decision` | The body holds a decision block (below). The issue is not ready until the label is removed. |
| Waiting on evidence? | `needs:info` | Needs a measurement, a reproduction, a platform run, or a third party. Not ready until removed. |
| Blocked by other work? | native "blocked by" link | No label. The link names the blocker and clears itself when the blocker closes. |
| Where in the program? | `phase:N` (existing) | The only record of phase membership once stage 2 lands. |
| What bundles together? | parent issue with sub-issues | A PR-sized work package. Ordering between packages is "blocked by" links between the parents. |
| Never ranked | `tracking`, `dependencies`, `nightly-test-failure` | Trackers and bot streams. |

Rules:

1. **Exactly one** `priority:*` label per triaged issue.
2. **Decisions block by link.** When one decision gates several issues, file it as its
   own issue titled `Decide: <question>` with `needs:decision`, and make the gated issues
   "blocked by" it. A decision about a single issue is just `needs:decision` on that issue.
3. **Decision block** (issue body section, verbatim headings):

   ```markdown
   ## Decision needed
   **Question:** <one sentence>
   **Options:**
   1. <option> — <consequence>
   2. <option> — <consequence>
   **Recommendation:** <option and why, one line>
   **Default if no answer:** <what happens if the maintainer stays silent>
   ```

4. **Work packages.** Any open issue with at least one open sub-issue is a package. A
   package is titled `Phase <N> PR <letter>: <scope>` (for example
   `Phase 6 PR G: grype leaves`), labelled `phase:N` and `priority:*`, with the issues the
   PR will close as sub-issues. The package's priority governs; its children need no
   priority label. The PR's squash commit message closes the parent and every sub-issue.
   Weekly version-checker issues are never sub-issues: the checker replaces them weekly,
   so the PR closes whichever one is open when it lands.
5. **In progress = assigned.** When the maintainer picks an item, the agent assigns it to
   the maintainer (`gh issue edit N --add-assignee @me`). An assigned item leaves the ready
   pool until it closes, which covers both an open PR and the wait between merge to `dev`
   and the sync to `main`. If work stops unfinished, the assignee is removed.
6. **The agent proposes; the maintainer confirms.** The agent never applies a
   `priority:*` label directly. It files a label suggestion with a one-line rationale and a
   confidence (`LOW`/`MEDIUM`/`HIGH`), or lists proposals in chat for a batch "yes". The
   maintainer accepts in the GitHub UI or tells the agent to apply them.
   `needs:*` labels, phase labels and links may be set directly, because they record
   facts, not judgement.
7. **No private detail in issue text.** The session-end skill's existing private-name check
   (run on added lines and commit messages before a push) also runs on every issue and
   comment body the agent writes, before `gh issue create` or `gh issue comment`.

## 5. Ranking: `scripts/dev/backlog.py next`

One read, no writes. Input is

```bash
gh issue list --state open --limit 500 \
  --json number,title,labels,createdAt,assignees,parent,subIssuesSummary,blockedBy,blocking
```

which carries the edges and their state (§3). Parsing and ranking are pure functions,
unit-tested from recorded JSON fixtures. The script refuses to run on `gh` older than 2.94.

**Units.** The ranking works on *units*: a package (an open issue with at least one open
sub-issue) or a standalone issue (an open issue with no open parent). An issue whose parent
is open is a child: it is shown under its package, never ranked on its own. An issue whose
parent is closed is standalone.

**Ready pool.** A unit is ready when it:

- carries `priority:p1` or `priority:p2` (`p3` is parked and never ranked; its count is shown);
- carries neither `needs:decision` nor `needs:info`;
- carries none of `tracking`, `dependencies`, `nightly-test-failure`;
- has zero open blockers;
- has no assignee (assigned = in progress, §4 rule 5).

A package whose own fields pass is ready even if some children are blocked or waiting on
`needs:*`; the output says so (`1 child waits on a decision`). A package whose children are
all closed is not ranked; it is reported as "close it?".

**Order:** priority (p1 before p2), then lowest `phase:N` (no phase sorts after every
phase), then how many open issues it blocks (more first), then oldest.

**"Blocks" count** for an item: the open issues that list it in `blockedBy`, where a blocked
package counts as one plus its open children. Direct links only; no transitive closure.

**Side lists**, computed over all open issues (not only the ready pool):

- *Decisions waiting on you:* open issues with `needs:decision`, oldest first, with age.
- *Biggest unblocker:* the open issue with the highest "blocks" count, ready or not (a
  `Decide:` issue is often it).
- *In progress:* assigned units.
- *Untriaged:* units with no `priority:*` label, excluding the never-ranked labels and the
  weekly version-checker issues. Children of packages are never untriaged.
- Counts: `needs:info`, `priority:p3`, pending agent suggestions, open p1 against the cap.

**Output** (text by default, `--json` for the skills):

```text
Top 3 ready
  1. #AAAA p1 phase:6  Phase 6 PR G: grype leaves  (2 sub-issues, unblocks 1 package)
  2. ...
In progress: #CCCC Phase 6 PR D: image discovery and validation (assigned)
Decisions waiting on you (oldest first)
  #BBBB 23d  Decide: ...
Biggest unblocker: #AAAA (frees 1 package with 4 issues)
Untriaged: N · needs:info: N · p3 parked: N · pending suggestions: N · open p1: N/7
```

A `check` subcommand (stage 2, §7) reports hygiene problems: more than one priority label,
`needs:decision` without the decision block, p1 over the cap, a package with no open
children, a child carrying its own priority label.

## 6. Session integration (maintainer-local skills)

**Session start.** Replace the roster read-out with `backlog.py next` output. The plan
step becomes: red instruments and red CI first (unchanged), then the top 3, then the
decisions waiting. Surface the untriaged count and pending suggestions; offer a triage
batch when either is non-zero. When the maintainer picks an item, the agent assigns it to
the maintainer (§4 rule 5).

**Session end.** Filing becomes: run the private-name check on the body (§4 rule 7);
search for duplicates; file with `phase:N` if it belongs to the program; propose
`priority:*` as a suggestion with rationale; add `needs:*`, parent and "blocked by" links
when known. An item left unfinished is unassigned. A package's PR squash message closes the
parent and every sub-issue; until stage 2 the session-end skill checks that by hand, since
`closers --check` does not see unrostered parents. The rolling handoff stops carrying
pending decisions and blockers: they live on issues, and the handoff lists issue numbers
only.

`/done` is at its 500-line cap, so its edits replace text: the roster-scheduling
paragraphs that stage 2 deletes are condensed in stage 1 to make room.

## 7. Rollout

**Stage 1: additive; the current gate stays green.**

1. Create `priority:p1`, `priority:p2`, `priority:p3`, `needs:decision`, `needs:info` with
   their definitions as descriptions.
2. Move the 9 `disposition:DEFER-POST-1.1.0` issues to `priority:p3` and delete the old label.
3. **Audit exemption for packages**, in one PR with unit tests: in `phase_audit.py`, an open
   issue with at least one sub-issue is exempt from the "unclaimed" check, from the
   label-drift check, and from `labels --apply` stripping its `phase:N` label. The audit
   reads sub-issue counts from REST (`sub_issues_summary` via `gh api`), which works with
   any `gh` version the CI runner has. This is the only stage-1 code change to the audit.
4. **Sequencing:** step 3 merges into `dev` **and** `dev` is synced to `main` before any
   package is filed, because PRs into `main` run `main`'s copy of the audit and the weekly
   routine reads its result.
5. Add `scripts/dev/backlog.py` with `next`, plus unit tests on recorded fixtures.
6. Phase 6: file the remaining work packages (D, G, Y, E, F) as parents with their issues
   as sub-issues (G without the grype version-checker issue, §4 rule 4), link F as blocked
   by G and Y (the PR sequence table in
   `docs/superpowers/plans/2026-10-29-phase-6-grype-yara-x-golden.md`), and assign D,
   whose PR #1529 is open.
7. Triage the open issues: the agent proposes priorities in batches as label suggestions;
   the maintainer accepts or corrects. The first batch also confirms that pending
   suggestions show in the GitHub UI (§8).
8. Update the session skills (§6).
9. Document the labels for contributors in `CONTRIBUTING.md` (a short table).

**Exit criteria for stage 1:** `backlog.py next` on the live repo yields a top 3 the
maintainer agrees with on first read; F's package is absent from the ready pool until G and
Y close; D shows as in progress, not ready; `phase-audit` stays green on `dev` and `main`
throughout.

**Stage 2: after two or three working sessions on stage 1.**

1. Remove the issue rosters and summary-table counts from the program plan; the plan
   states that `phase:N` labels are the roster.
2. Rewrite the audit, keeping the job and check name `phase-audit` (the weekly routine
   consumes it) and keeping it stdlib-only:
   - `verify` reports untriaged issues but **never fails on them**: the session-start
     count is the forcing function (maintainer's decision, 2026-10-31), so an issue filed
     by a contributor or a bot never turns PRs red. It fails only on a contradiction: two
     `priority:*` labels, or two `phase:N` labels, on one issue.
   - `check` (from §5) prints the softer hygiene problems (p1 over cap, missing decision
     block, empty package, child with a priority label); none of them fails.
   - `closers --check` reads `phase:N` labels instead of `plan.phases`, so packages and
     their children are covered.
   - `derive` and `labels` are deleted, with the CI step that runs `derive`.
3. Remove the roster-scheduling rules from the session-end skill.

## 8. Risks

| Risk | Mitigation |
|---|---|
| Labels are untyped: two priorities on one issue | `check` flags it; suggestions replace rather than add |
| Priority inflation | Soft cap on p1, shown every session |
| Untriaged pile grows | Counted every session; triage offered when non-zero |
| Parent blockers not propagated by GitHub | The script propagates; covered by a unit test |
| `gh` older than 2.94 on some machine | The script fails fast with the required version |
| Agent edits indistinguishable from the maintainer's (same token) | Accepted; suggestions carry a rationale, and the timeline records every change |
| Pending suggestions not visible in the UI as expected | Verify on the first triage batch; fall back to chat proposals |
| A stale assignment hides an item from the ranking | "In progress" is listed every session, so a forgotten one is visible |
| A ready package hides a blocked child | The output names children that wait, under their package |
| Packages filed before the exemption reaches `main` turn `phase-audit` red | Stage 1 step 4 sequencing: merge and sync first |

## 9. Later: organization fields

If the repo ever moves to the `JMoGaming` organization (or GitHub's private preview of
fields on user-owned repos reaches it), the labels map one-to-one onto the default
Priority field (`p1→High`, `p2→Medium`, `p3→Low`; `Urgent` unused) by a one-off script,
and suggestions carry over (`FIELD` instead of `LABEL`). Measured costs of a move, for the
record: GHCR images publish to `ghcr.io/jmogaming/...` automatically (`release.yml` uses
`github.repository_owner`); the old `ghcr.io/jimmy058910/...` image stays pullable but
freezes and loses its repository link; the new package starts private; PyPI trusted
publishing needs a publisher for the new owner before the move; 687 owner mentions in 130
tracked files.

## 10. Alternatives considered

Evaluated 2026-10-31 (research and a hands-on trial):

- **Beads (`bd`)**: faithful import, useful `ready` with parent propagation, but default-on
  telemetry, ~4-minute no-op re-sync (~780 API calls), comments and authors lost, opaque
  IDs, and an agent prompt that contradicts this repo's rules. Rejected after trial.
- **Linear, ZenHub, Plane**: each syncs only some fields, so facts split across two
  stores; Linear and ZenHub free tiers cap at 250 issues (this repo has 778).
- **Backlog.md, Task Master, git-bug, tk**: no import of an existing GitHub history,
  planning files in the public tree, default-on telemetry (Task Master), or a lossy bridge
  (git-bug).
- **GitHub Projects with a Priority field**: two objects per issue, no server-side sort by
  field, and a token scope this setup does not need otherwise.
- **Free organization**: see §9.

## 11. Calls made by the designer (check these)

Settled during review without the maintainer; each is reversible before stage 1 lands.

1. Packages carry `phase:N`; the stage-1 audit exemption covers "unclaimed", label drift
   and `labels --apply` for any issue with sub-issues.
2. "In progress" is an assignee on the item, not a label.
3. The ranking reads `gh issue list --json` with edges (needs `gh` 2.94+); the CI audit
   reads REST counts so it does not depend on the runner's `gh`.
4. `priority:p3` is never ranked, only counted.
5. A package is ranked as one unit with its own priority; its children are never ranked
   separately, and a waiting child does not hold the package back.
6. "Blocks" counts direct links; a blocked package counts as one plus its open children.
7. "Untriaged" excludes never-ranked labels, version-checker issues and package children.
8. Weekly version-checker issues never become sub-issues.
9. The private-name check runs on issue and comment bodies in the session-end skill.
10. Stage 2 keeps the `phase-audit` job and check name; only a contradiction (two priority
    or two phase labels on one issue) fails it.
11. Agent proposals use GitHub's label suggestions, with chat proposals as the fallback.

## 12. Left to the builder

- Internal structure of `backlog.py`, fixture format, and text layout of the output.
- Exact GraphQL for suggestions (shapes are in §3) and batching of the triage pass.
- Wording of the `CONTRIBUTING.md` table.
