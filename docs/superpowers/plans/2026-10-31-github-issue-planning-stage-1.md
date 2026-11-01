# GitHub-native issue planning, stage 1: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make GitHub Issues the single source for "what next": priority labels, decision
and evidence labels, native blockers and work packages, and a script that prints the top 3
ready items, with the current `phase-audit` gate kept green throughout.

**Architecture:** Two stdlib-only scripts. `scripts/dev/phase_audit.py` gains one exemption
(issues with sub-issues are work packages). A new `scripts/dev/backlog.py` reads one
`gh issue list --json` call, ranks with pure functions, and files or accepts GitHub label
suggestions through `gh api graphql`. GitHub-side setup (labels, packages, triage) and the
maintainer-local session skills follow once the code is on `dev` and `main`.

**Tech Stack:** Python 3.12 stdlib, `gh` CLI (2.94+ for `backlog.py`, any version for
`phase_audit.py`), pytest, GitHub REST and GraphQL.

**Spec:** `docs/superpowers/specs/2026-10-31-github-issue-planning-design.md`. Stage 2
(roster removal, audit rewrite) is out of scope and gets its own plan.

**Deviation from the spec:** §7 step 2 says delete `disposition:DEFER-POST-1.1.0`. Deleting a
label strips it from every issue, including the 47 closed issues that carry it as history.
This plan retires it instead (Task 5).

## Global Constraints

- Branch: rename `docs/issue-planning-design` to `feature/issue-planning-stage-1`; no upstream
  until Task 6 pushes it. Never commit to `dev` directly.
- Both scripts are stdlib-only (the `phase-audit` CI job runs without `uv sync`).
- `subprocess.run` with a list, never `shell=True`; `encoding="utf-8", errors="replace"`;
  `timeout=120`; a non-zero `gh` exit raises `RuntimeError` (same contract as
  `phase_audit._gh`).
- `backlog.py` refuses `gh` older than 2.94.0. `phase_audit.py` must keep working with any
  `gh`, so it uses only `gh issue list`, `gh repo view` and `gh api` REST.
- Script output templates are ASCII; issue titles print as given, and `main()` calls
  `harden_console_streams()` (bootstrap as in `scripts/dev/check_doc_links.py`).
- Tests live in `tests/unit/`, never call `gh` or the network, and pass on Windows CI
  (bytes I/O, `encoding="utf-8"` on every read).
- Label names, colors and descriptions are exactly those in Task 5.
- Every GitHub write (labels, issues, suggestions, PR, merge, sync to `main`) runs only after
  the maintainer's go-ahead for that task.
- No AI-attribution markers in commits, PR bodies or issue text; no private host or
  repository names in any issue or comment body.
- Before every commit: `make fmt && make lint` and the task's tests; before the PR:
  `make test-fast`.

## Review Focus

1. **Contradictory priorities** (an issue with both `priority:p1` and `priority:p2`) rank by
   the highest and are not dropped. Test in Task 2.
2. **A blocked-by cycle** (A blocked by B, B blocked by A) terminates, and neither is ready.
   Test in Task 2.
3. **Phase labels that are not a single integer** (`phase:x`, or two phase labels): non-numeric
   ones are ignored, and the lowest numeric phase wins. Test in Task 2.
4. **More open issues than the fetch limit**: the report says it is truncated instead of
   ranking a partial list silently. Test in Task 2.
5. **`gh` missing, unauthenticated or failing**: one-line error on stderr, exit 2, no
   traceback. Test in Task 2.

---

### Task 1: Work-package exemption in `phase_audit.py`

**Files:**
- Modify: `scripts/dev/phase_audit.py` (`_unclaimed` at :528, `_report_exempt` at :540,
  `cmd_labels` sweep at :732-750, `cmd_unclaimed` at :769, `cmd_verify` sweep at :824-828)
- Test: `tests/unit/test_phase_audit.py`

**Interfaces:**
- Produces: `fetch_packages() -> set[int]`: every issue number, open or closed, that has at
  least one sub-issue.
- Produces: `_unclaimed(plan, issues, packages: set[int]) -> tuple[list[int], list[int], list[int]]`
  returning `(unclaimed, version_exempt, package_exempt)`.

- [ ] **Step 1: Rename the branch**

Run: `git -C ~/.cache/jmo-wt/issue-planning branch -m feature/issue-planning-stage-1`
Expected: `git -C ~/.cache/jmo-wt/issue-planning status -sb` shows `## feature/issue-planning-stage-1`.

- [ ] **Step 2: Write the failing tests**

Add an autouse fixture so every existing test sees no packages, then the new tests:

```python
@pytest.fixture(autouse=True)
def _no_packages(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(phase_audit, "fetch_packages", lambda: set())

def test_a_work_package_is_exempt_from_unclaimed_and_says_so(...):
    # _unclaimed_world(extra=Issue(400, "OPEN", {"phase:6", "priority:p2"}))
    # fetch_packages -> {400}
    assert cmd_unclaimed(plan) == 0 and cmd_verify(plan) == 0
    assert "work package" in out and "#400" in out

def test_a_closed_work_package_keeps_its_phase_label(...):
    # extra=Issue(401, "CLOSED", {"phase:6"}), fetch_packages -> {401}
    assert cmd_verify(plan) == 0

def test_an_unscheduled_phase_label_without_sub_issues_still_drifts(...):
    # negative control: extra=Issue(402, "OPEN", {"phase:6"}), fetch_packages -> set()
    assert cmd_verify(plan) == 1 and "#402" in out and "schedules it nowhere" in out

def test_labels_apply_leaves_a_work_package_phase_label_alone(...):
    # _labels_world(extra={400: Issue(400, "OPEN", {"phase:6"})}), fetch_packages -> {400}
    assert not any(c[:3] == ("issue", "edit", "400") for c in calls)
    assert ("issue", "edit", "900", "--remove-label", "phase:9") in calls  # control

def test_fetch_packages_searches_issues_with_sub_issues(...):
    # fake _gh: ("repo", "view", ...) -> "o/r\n"; ("api", ...) -> "12\n34\n"
    assert fetch_packages() == {12, 34}
    # the api call is a REST search: "search/issues" in args, and its q= value
    # contains "repo:o/r", "is:issue" and "has:sub-issue"
```

`_labels_world` gains an `extra: dict[int, Issue] | None = None` parameter merged into its
issues.

- [ ] **Step 3: Run them to verify they fail**

Run: `uv run pytest tests/unit/test_phase_audit.py -q -k "package or sub_issues or drifts"`
Expected: FAIL (`fetch_packages` does not exist).

- [ ] **Step 4: Implement**

`fetch_packages()`: `_gh("repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner")`,
then `_gh("api", "-X", "GET", "search/issues", "--paginate", "-f",
f"q=repo:{repo} is:issue has:sub-issue", "--jq", ".items[].number")`; parse one int per
non-empty line. `cmd_unclaimed`, `cmd_verify` and `cmd_labels` call it once. `_unclaimed`
removes packages from the absent set before the version check. A new `_report_packages()`
prints `exempt: N work package(s) (issues with sub-issues): #...` when non-empty. Both
"scheduled nowhere" loops skip numbers in `packages`. Add one paragraph to the module
docstring under "THE ONE KIND OF ISSUE THAT NEEDS NO HOME" naming the second kind and why.

- [ ] **Step 5: Run the whole module's tests**

Run: `uv run pytest tests/unit/test_phase_audit.py -q`
Expected: all pass, including the existing 900-line suite unchanged apart from the fixture.

- [ ] **Step 6: Check against live GitHub (read-only)**

Run: `uv run python scripts/dev/phase_audit.py verify`
Expected: exit 0, and no "work package" line (none exist yet).

- [ ] **Step 7: Commit**

```bash
git add scripts/dev/phase_audit.py tests/unit/test_phase_audit.py
git commit -m "feat(phase-audit): exempt work-package parents (issues with sub-issues)"
```

---

### Task 2: `backlog.py next`

**Files:**
- Create: `scripts/dev/backlog.py`
- Test: `tests/unit/test_backlog.py`

**Interfaces:**
- Produces constants: `PRIORITIES = {"priority:p1": 1, "priority:p2": 2, "priority:p3": 3}`,
  `NEEDS = ("needs:decision", "needs:info")`,
  `NEVER_RANKED = ("tracking", "dependencies", "nightly-test-failure")`, `P1_SOFT_CAP = 7`,
  `MIN_GH = (2, 94, 0)`, `FETCH_LIMIT = 500`,
  `GH_FIELDS = "number,title,labels,createdAt,assignees,parent,subIssuesSummary,blockedBy,blocking"`.
- Produces `@dataclass(frozen=True) class Item` with `number: int`, `title: str`,
  `labels: frozenset[str]`, `created_at: datetime`, `assignees: tuple[str, ...]`,
  `parent: int | None`, `sub_total: int`, `sub_open: int`, `open_blockers: tuple[int, ...]`,
  `open_blocking: tuple[int, ...]`, and properties `priority -> int | None` (lowest number
  among its priority labels), `phase -> int | None` (lowest numeric `phase:N`),
  `is_package -> bool` (`sub_open > 0`).
- Produces `parse_items(rows: list[dict[str, Any]]) -> dict[int, Item]`,
  `units(items) -> list[Item]`, `blocks_count(item, items) -> int`,
  `is_ready(item) -> bool`, `rank(items) -> list[Item]`,
  `build_report(items, now: datetime, pending: int, top_n: int = 3, truncated: bool = False) -> Report`,
  `render_text(report) -> str`, `report_json(report) -> dict[str, Any]`,
  `require_gh(version_text: str) -> None`, `fetch_items() -> tuple[dict[int, Item], bool]`,
  `main(argv: list[str] | None = None) -> int`.
- `Report` fields: `top`, `in_progress`, `decisions: list[tuple[Item, int]]` (age in days),
  `biggest_unblocker: tuple[Item, int] | None`, `close_candidates`,
  `waiting_children: dict[int, list[Item]]`, `untriaged`, `needs_info`, `parked_p3`,
  `open_p1`, `pending_suggestions`, `truncated`.

Rules, from spec §5: a *unit* is a package or an open issue whose parent is absent from the
open set. Ready = priority 1 or 2, no `NEEDS` label, no `NEVER_RANKED` label, no open
blocker, no assignee. Order key: `(priority, phase or 10**6, -blocks_count, created_at)`.
`blocks_count` = for each open issue it blocks, 1 plus that issue's `sub_open` if it is a
package; direct links only. Untriaged = units without a priority and without a
`NEVER_RANKED` label. Decisions = all open issues with `needs:decision`, oldest first.
Biggest unblocker = highest `blocks_count` over all open issues, if above 0.
Close candidates = open issues with `sub_total > 0` and `sub_open == 0`.

- [ ] **Step 1: Write the failing tests**

A helper `row(n, *, labels=(), created="2026-10-01T00:00:00Z", assignees=(), parent=None,
sub=(0, 0), blocked_by=(), blocking=())` builds `gh issue list --json` rows, where
`blocked_by` and `blocking` hold `(number, "OPEN" | "CLOSED")` pairs and `sub` is
`(total, completed)`. Tests and their key assertions:

- `test_p1_ranks_above_p2_whatever_the_phase`: p1 `phase:9` before p2 `phase:6`.
- `test_within_a_priority_lower_phase_then_more_blocked_then_older`: three p2 rows ordered
  by phase, then by `blocks_count`, then by `createdAt`.
- `test_no_priority_and_p3_are_never_ranked_but_counted`: `untriaged == 1`, `parked_p3 == 1`.
- `test_needs_and_never_ranked_labels_exclude`: each of the five labels removes the row.
- `test_an_open_blocker_excludes_and_a_closed_one_does_not`.
- `test_an_assigned_unit_is_in_progress_not_ready`.
- `test_children_of_an_open_package_are_not_ranked_on_their_own`.
- `test_a_blocked_package_hides_its_children`: package F blocked by open G; F and its four
  children absent from `top`.
- `test_a_child_whose_parent_is_closed_is_standalone`.
- `test_a_package_with_a_waiting_child_is_ready_and_names_the_child`: the child with
  `needs:decision` appears in `waiting_children[pkg]`.
- `test_a_package_with_no_open_children_is_a_close_candidate_not_ranked`.
- `test_blocks_count_counts_a_blocked_package_as_one_plus_its_open_children`: G blocks F
  (4 open children), so `blocks_count(G) == 5`.
- `test_biggest_unblocker_can_be_an_unready_decision_issue`.
- `test_untriaged_excludes_never_ranked_labels_and_package_children`.
- `test_decisions_are_oldest_first_with_age_in_days`: `now` fixed at 2026-10-31, rows
  created 10-08 and 10-21, so ages are `[23, 10]`.
- `test_render_text_has_every_section`: contains `Top 3 ready`, `In progress`,
  `Decisions waiting on you`, `Biggest unblocker`, `open p1: 1/7`, and a title with a
  non-ASCII dash renders without raising.
- `test_require_gh_rejects_2_46_and_accepts_2_94_and_2_103`: `SystemExit` with code 2 for
  `gh version 2.46.0 (...)`; no exception for 2.94.0 and 2.103.0.
- `test_fetch_items_passes_list_args_and_flags_truncation`: a stubbed `_gh` records
  `("issue", "list", "--state", "open", "--limit", "500", "--json", GH_FIELDS)` and returns
  500 rows, so `truncated is True` and `render_text` warns.
- `test_contradictory_priorities_rank_by_the_highest` (Review Focus 1).
- `test_a_blocked_by_cycle_terminates_and_neither_is_ready` (Review Focus 2).
- `test_non_numeric_phase_is_ignored_and_lowest_phase_wins` (Review Focus 3).
- `test_gh_failure_exits_2_with_one_line_on_stderr`: `fetch_items` raising `RuntimeError`
  makes `main(["next"])` return 2, with stderr starting `backlog: gh failed` (Review Focus 5).

- [ ] **Step 2: Run them to verify they fail**

Run: `uv run pytest tests/unit/test_backlog.py -q`
Expected: FAIL (module not found).

- [ ] **Step 3: Implement `scripts/dev/backlog.py`**

The module docstring states the spec path and the ready rule. `main` has an argparse
subcommand `next [--json] [--top N]`: `require_gh(gh --version)`, `fetch_items()`,
`pending_suggestions()` from Task 3 (stubbed to 0 until then), `build_report(...,
now=datetime.now(timezone.utc))`, then print the text or JSON. Output layout as in spec §5,
with `|` as the separator in the counts line.

- [ ] **Step 4: Run the tests**

Run: `uv run pytest tests/unit/test_backlog.py -q`
Expected: all pass.

- [ ] **Step 5: Run it against the live repo (read-only)**

Run: `uv run python scripts/dev/backlog.py next`
Expected: exit 0. With no priority labels yet, `Top 3 ready` is empty and
`Untriaged:` is about 104 (105 open, less #1492 with `dependencies`). Paste the counts line
into the task notes for the PR.

- [ ] **Step 6: Commit**

```bash
git add scripts/dev/backlog.py tests/unit/test_backlog.py
git commit -m "feat(dev): backlog.py next ranks ready issues from GitHub state"
```

---

### Task 3: Label suggestions: `suggest`, `accept`, pending count

**Files:**
- Modify: `scripts/dev/backlog.py`
- Test: `tests/unit/test_backlog.py`

**Interfaces:**
- Consumes: `_gh` from Task 2.
- Produces: `pending_suggestions() -> dict[int, list[str]]` (issue number to pending label
  names, open issues only), `suggest_label(number: int, label: str, rationale: str,
  confidence: str) -> None`, `accept_suggestions(numbers: list[int]) -> list[str]` (labels
  applied), and subcommands
  `suggest N LABEL --rationale TEXT [--confidence {LOW,MEDIUM,HIGH}]` (default MEDIUM) and
  `accept N [N ...]`. `next` reports `sum(len(v) for v in pending_suggestions().values())`.

GraphQL shapes, measured 2026-10-31 (spec §3):
- Suggest: `addLabelsToLabelable(input: {labelableId, labels: [{labelId, suggest: true,
  rationale, confidence}]})`. Do **not** use `updateIssue(labels: ...)`, whose list
  semantics were only tested on an issue with no labels.
- Read: `repository.issues(states: OPEN) { nodes { number pendingSuggestions { __typename
  ... on PendingLabelSuggestion { label { name id } } } } }`, paginated (`pendingSuggestions`
  takes no arguments).
- Accept: `applyPendingIssueSuggestions(input: {issueId, actorId: viewer.id,
  suggestions: [{kind: LABEL, labelId}]})`.

- [ ] **Step 1: Write the failing tests**

- `test_suggest_builds_an_add_labels_mutation_with_suggest_true`: a stubbed `_gh` captures the
  GraphQL body. It contains `addLabelsToLabelable` and not `updateIssue`, and the variables
  carry `suggest: True`, the rationale, and `confidence: "HIGH"`.
- `test_suggest_rejects_a_label_outside_priority_and_needs`: `suggest 12 bug` exits 2,
  because only `priority:*` and `needs:*` are suggestable.
- `test_pending_suggestions_parses_label_suggestions_only`: a fixture with one
  `PendingLabelSuggestion` and one `PendingFieldSuggestion` returns `{12: ["priority:p2"]}`.
- `test_accept_applies_each_pending_label_by_id`: the mutation has `kind: "LABEL"` and the
  pending label's id.
- `test_accept_with_nothing_pending_writes_nothing`.

- [ ] **Step 2: Run them to verify they fail**

Run: `uv run pytest tests/unit/test_backlog.py -q -k "suggest or accept or pending"`
Expected: FAIL.

- [ ] **Step 3: Implement**, with GraphQL bodies sent through `gh api graphql --input -`.
  JSON is built with `json.dumps`, never string-formatted into the query.

- [ ] **Step 4: Run the tests**

Run: `uv run pytest tests/unit/test_backlog.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add scripts/dev/backlog.py tests/unit/test_backlog.py
git commit -m "feat(dev): backlog.py files and accepts label suggestions"
```

---

### Task 4: Contributor docs

**Files:**
- Modify: `CONTRIBUTING.md` (new `### Issue labels` under `## How to get started`, after line 13)
- Modify: `CLAUDE.md` ("Where Deferred Work Goes" table, first row)

- [ ] **Step 1: Add the table** with `priority:p1|p2|p3`, `needs:decision`, `needs:info`
  (each with its Task 5 description), `phase:N`, and one line on work packages (a parent
  issue whose sub-issues one PR closes) and on "blocked by" links. Add the decision-block
  template from spec §4 rule 3, and the `Decide: <question>` title for a decision that gates
  several issues (spec §4 rule 2).
- [ ] **Step 2: CLAUDE.md row 1** becomes "**GitHub issue** (`technical-debt` /
  `enhancement`, with a `priority:*` label proposed by the agent and confirmed by the
  maintainer) + `# TODO(issue-#):` at the site".
- [ ] **Step 3: Verify**

Run: `uv run python scripts/dev/check_doc_links.py && uv run pre-commit run markdownlint-cli2 --files CONTRIBUTING.md CLAUDE.md`
Expected: both pass.

- [ ] **Step 4: Commit**

```bash
git add CONTRIBUTING.md CLAUDE.md
git commit -m "docs: priority, decision and blocker conventions for issues"
```

---

### Task 5: Labels on GitHub (write; maintainer go-ahead)

Create with `gh label create NAME --color HEX --description TEXT`:

| Name | Color | Description (exact) |
|---|---|---|
| `priority:p1` | `B60205` | Someone would notice in the release: user-facing defect, security/data flaw, red gate. Cap ~7 open. |
| `priority:p2` | `D93F0B` | Planned and wanted; waiting harms nobody. The normal state of phase work. |
| `priority:p3` | `C2E0C6` | Parked on purpose; never ranked. Close as not planned if still p3 after two phases close. |
| `needs:decision` | `5319E7` | Waiting on the maintainer. Body has Question, Options, Recommendation, Default if no answer. |
| `needs:info` | `FBCA04` | Waiting on evidence: a measurement, a reproduction, a platform run, or a third party. |

- [ ] **Step 1: Create the five labels.**
- [ ] **Step 2: Move the 9 open deferred issues** #48 #53 #54 #770 #943 #947 #972 #998 #999:
  `gh issue edit N --add-label priority:p3 --remove-label disposition:DEFER-POST-1.1.0`.
- [ ] **Step 3: Retire the old label**:
  `gh label edit disposition:DEFER-POST-1.1.0 --description "Retired 2026-10-31: replaced by priority:p3. Kept for the history of closed issues."`
- [ ] **Step 4: Verify**

Run: `gh issue list --state open --label disposition:DEFER-POST-1.1.0 --json number --jq length; gh issue list --state open --label priority:p3 --json number --jq length; uv run python scripts/dev/phase_audit.py verify`
Expected: `0`, `9`, then exit 0.

---

### Task 6: PR, merge, sync to `main` (write; maintainer go-ahead at each step)

- [ ] **Step 1: Full local gate**

Run: `make fmt && make lint && make test-fast`
Expected: all pass.

- [ ] **Step 2: Push and open the PR into `dev`**, titled
  `feat: GitHub-native issue planning, stage 1`. Its body carries the evidence gate
  (CLAUDE.md): the verification CI cannot provide is a live run, so paste the
  `backlog.py next` counts line and the `phase_audit.py verify` exit code, both run from
  this branch against live GitHub.
- [ ] **Step 3: CI green, and read the `windows-2022` shard's log** for the
  `tests/unit/test_backlog.py` and `test_phase_audit.py` counts: no new skips, 0 failed.
- [ ] **Step 4: Merge** (squash; maintainer go-ahead).
- [ ] **Step 5: Sync `dev` to `main`** as a fast-forward push of the full `origin/dev` SHA,
  after `git merge-base --is-ancestor origin/main origin/dev` and
  `phase_audit.py closers --check` (`MISSING: 0`) (maintainer go-ahead).
- [ ] **Step 6: Verify**

Run: `git rev-parse origin/main origin/dev`
Expected: identical SHAs, and `scripts/dev/phase_audit.py` on `origin/main` contains
`fetch_packages`.

---

### Task 7: Phase 6 work packages (write; maintainer go-ahead; only after Task 6)

| Package title | Sub-issues |
|---|---|
| `Phase 6 PR D: image discovery and validation` | #1405 #1415 #1416 |
| `Phase 6 PR G: grype leaves` | #1372 (not #1492, spec §4 rule 4) |
| `Phase 6 PR Y: yara-x and signature-base` | #1282 #1413 |
| `Phase 6 PR E: rows and tables keyed by tool; KICS's line floor` | #1354 #1370 #1410 #1430 #1431 |
| `Phase 6 PR F: golden for every adapter; BenchProctor` | #1097 #1349 #1365 #1502 |

- [ ] **Step 0: Check PR D.** `gh pr view 1529 --json state,mergedAt`. If it has merged, file
  no D package (its squash closes #1405 #1415 #1416 at the next sync) and skip Step 4.
- [ ] **Step 1: File each** with `gh issue create --label phase:6`. The body has two lines:
  the PR's scope from the Phase 6 plan's sequence table, and "The PR's squash commit message
  closes this issue and every sub-issue." D's body also says "In progress: PR #1529."
- [ ] **Step 2: Attach sub-issues**: `gh issue edit <pkg> --add-sub-issue <list>`.
- [ ] **Step 3: Order:** `gh issue edit <F> --add-blocked-by <G>,<Y>`.
- [ ] **Step 4: Mark D in progress:** `gh issue edit <D> --add-assignee @me`.
- [ ] **Step 5: Verify**

Run: `uv run python scripts/dev/phase_audit.py verify` from checkouts of `origin/dev` and `origin/main`, then `uv run python scripts/dev/backlog.py next`
Expected: both audits exit 0 and print `exempt: 5 work package(s)`. The ranking lists D
under `In progress`, never lists F, and shows `Biggest unblocker` as G or Y.

---

### Task 8: Triage pass (write; maintainer confirms every priority)

- [ ] **Step 1: Probe once.** On one untriaged issue the maintainer names, run
  `backlog.py suggest N priority:p2 --rationale "..." --confidence MEDIUM`, then check two
  things. First, `gh issue view N --json labels` is unchanged. Second, the maintainer sees the
  suggestion on the issue page in the GitHub UI. If either fails, remove anything applied
  and switch to chat proposals with `gh issue edit --add-label` after a "yes".
- [ ] **Step 2: Batches of up to 15.** For each untriaged unit (packages included), show a
  table in chat (number, title, proposed priority, one-line rationale), then file the
  suggestions. The maintainer accepts in the UI or says "accept batch", which runs
  `backlog.py accept`. Corrections go in with `gh issue edit`.
- [ ] **Step 3: Verify**

Run: `uv run python scripts/dev/backlog.py next`
Expected: `Untriaged: 0` (or only issues the maintainer chose to leave), `open p1` at most 7.

---

### Task 9: Session skills (maintainer-local, untracked; no commit)

**Files:**
- Modify: `.claude/skills/start/SKILL.md` (Phase C "What is open" block at :111-122;
  Phase E at :202-207; Output block at :213-227)
- Modify: `.claude/skills/done/SKILL.md` (private-name check at :103-119; Phase D at :145-245;
  Phase E handoff section 3)

- [ ] **Step 1: `/start`.**
  - Phase C: replace the `derive | grep` and `gh issue list --label phase:<N>` lines with
    `python scripts/dev/backlog.py next`, run from the `origin/dev` worktree like the rest of
    Phase C. Keep the PR list.
  - Phase E order: red instruments, red health, the handoff's re-checked items, the top 3,
    decisions waiting, then the user's ask. When the maintainer picks an item, run
    `gh issue edit N --add-assignee @me`.
  - Output: replace the `Open:` line with
    `Next: [#a #b #c] | decisions [n] | untriaged [n] | in progress [#..]`.
- [ ] **Step 2: `/done`.**
  - The commit-message grep at :103 also covers every issue and comment body written this
    session: pipe each body through the same pattern before `gh issue create` or
    `gh issue comment`.
  - Phase D filing: set `phase:N` for program work; propose priority with
    `backlog.py suggest`; add `needs:*`, a parent and "blocked by" links when known. Unassign
    an item left unfinished. A package's PR squash message closes the parent and every
    sub-issue; check that by hand.
  - Stage-1 note: any new issue that is not a package, including a `Decide:` issue, still
    follows the roster rule.
  - Handoff section 3 lists issue numbers only, no copied decisions or blockers.
  - Net line change must be 0 or negative: condense the dated anecdotes in Phase D
    ("Measured 2026-09-12 ...", "Measured 2026-09-25 ...") to one clause each, keeping
    every rule.
- [ ] **Step 3: Verify** with each skill's own self-check (the Python block at the end of
  each SKILL.md).
  Expected: `OK` for both, and each body under 500 lines.

---

### Task 10: Stage-1 acceptance

- [ ] **Step 1:** Run `uv run python scripts/dev/backlog.py next` with the maintainer.
  Expected: they agree with the top 3 on first read. F is absent while G or Y is open, and D
  shows as in progress.
- [ ] **Step 2:** Run `phase_audit.py verify` on `origin/dev` and on `origin/main`.
  Expected: both exit 0.
- [ ] **Step 3:** Run `/done`, which records stage 1 as complete and the date stage 2 becomes
  eligible (after two or three working sessions).
