---
name: jmo-issue-triage
description: >
  Periodic sweep of general open issues (bug, enhancement, technical-debt,
  documentation) PLUS nightly-test-failure trackers from app/github-actions.
  Classifies every covered issue into one of seven buckets — READY-TO-WORK,
  NEEDS-INFO, ROADMAP-TRACKING, STALE-NEGLECTED, DUPLICATE/SUPERSEDED,
  IMPLEMENTED-ON-MAIN, NIGHTLY-FAILURE-TRACKER — and produces a plan-mode
  review with explicit per-item recommendations. Issues with open linked
  PRs (Fixes/Closes/Resolves syntax) are non-closeable regardless of age.
  Designed for monthly cadence; does NOT touch Dependabot PRs
  (jmo-dependabot-triage) or tool-version update issues from
  app/github-actions labeled `dependencies` (jmo-tool-update-triage).
argument-hint: "[--dry-run | --execute] (default: dry-run, plan mode only)"
user-invocable: true
context: fork
allowed-tools: Bash, Read, Grep, Edit, Write
---

## Live Context

**Manual issues (NOT authored by app/github-actions):**
!gh issue list --repo jimmy058910/jmo-security-repo --state open --limit 100 --search "-author:app/github-actions" --json number,title,labels,createdAt,updatedAt,author,body,comments 2>/dev/null

**Nightly-failure trackers (app/github-actions issues labeled `nightly-test-failure`):**
!gh issue list --repo jimmy058910/jmo-security-repo --state open --limit 100 --label "nightly-test-failure" --json number,title,labels,createdAt,updatedAt,author,body 2>/dev/null

**Recent scheduled.yml workflow runs (used to detect "superseded by green" nightlies):**
!gh run list --repo jimmy058910/jmo-security-repo --workflow scheduled.yml --limit 30 --json databaseId,conclusion,createdAt,headBranch,event 2>/dev/null

**Recent release tags (used to detect nightly failures covered by a release fix):**
!git -C "$PWD" tag --sort=-creatordate --merged main | head -10

**Open issues labeled `bug`:**
!gh issue list --repo jimmy058910/jmo-security-repo --state open --label bug --limit 50 --json number,title,labels,updatedAt 2>/dev/null

**Open issues labeled `enhancement`:**
!gh issue list --repo jimmy058910/jmo-security-repo --state open --label enhancement --limit 50 --json number,title,labels,updatedAt 2>/dev/null

**Open issues labeled `technical-debt`:**
!gh issue list --repo jimmy058910/jmo-security-repo --state open --label technical-debt --limit 50 --json number,title,labels,updatedAt 2>/dev/null

**Open issues with roadmap or phase labels:**
!gh issue list --repo jimmy058910/jmo-security-repo --state open --label roadmap --limit 50 --json number,title,labels,updatedAt 2>/dev/null ; gh issue list --repo jimmy058910/jmo-security-repo --state open --search "label:phase-1 OR label:phase-2 OR label:phase-3 OR label:phase-4" --limit 50 --json number,title,labels,updatedAt 2>/dev/null

**Current branch (must be `main` for any write operations):**
!git -C "$PWD" rev-parse --abbrev-ref HEAD

---

## Purpose

Periodically (monthly cadence recommended) sweep the manual issue backlog AND the bot-authored `nightly-test-failure` backlog so actionable bugs don't stall, intentional ROADMAP placeholders aren't misidentified as neglect, and obsolete CI failure trackers (already root-caused by a later release) don't pile up indefinitely. Produces a structured plan classifying every covered issue into one of seven buckets:

1. **READY-TO-WORK** — clear scope, has reproduction (bugs) or problem statement (enhancements); candidate for `good first issue` if scoped small enough
2. **NEEDS-INFO** — bug missing reproduction steps or enhancement missing problem statement; comment to gather info, do NOT close
3. **ROADMAP-TRACKING** — intentional long-lived placeholder for `ROADMAP.md` items (issues with `roadmap` or `phase-*` labels, or titles matching `ROADMAP #N:` pattern); leave alone, NOT stale
4. **STALE-NEGLECTED** — non-roadmap issue with no activity for 90+ days, unlikely to be actioned, AND no merged PR resolves it; close with `wontfix` reason + explanation comment
5. **DUPLICATE/SUPERSEDED** — covered by another open issue; close pointing at the canonical issue
6. **IMPLEMENTED-ON-MAIN** — the original report is verifiably fixed on current `main` by a merged PR (verified via title/diff match or `git log -S` for a bug-specific string); close with a "fixed in #PR" acknowledgment, NOT `wontfix`
7. **NIGHTLY-FAILURE-TRACKER** — bot-authored issue labeled `nightly-test-failure`; classified into 4 sub-actions (BULK-CLOSE-PRE-FIX, SUPERSEDED-BY-GREEN, RECENT-LEAVE-OPEN, INVESTIGATE-MANUAL) per Rule 2.7. Most close as `completed` referencing the release tag or subsequent green nightly that resolved them.

Additionally, issues with **open** linked PRs (using `Fixes #N`/`Closes #N`/`Resolves #N` syntax) are non-closeable regardless of age — they appear in the plan as `LINKED-PR-PENDING` informational entries only.

The skill **never executes destructive actions without user approval**. It enters plan mode by default.

## When to Use

- Monthly cadence or before a new minor release cycle to ensure the backlog reflects current priorities.
- When the open issue count "feels wrong" (rule of thumb: >15 manual issues with no recent triage pass, OR nightly-failure trackers visibly piling up over multiple weeks).
- After a release that addressed nightly stability — most pre-release nightly-failure issues will be closeable as BULK-CLOSE-PRE-FIX.
- Before creating a roadmap or milestone to understand what's already tracked.
- When a new contributor asks "what can I work on?" — triage first, then point at READY-TO-WORK issues.

## When NOT to Use

- For Dependabot PRs or GH security alerts — use `/jmo-dependabot-triage` instead.
- For `app/github-actions` issues labeled `dependencies` (`Update <tool> to vX.Y.Z`) — use `/jmo-tool-update-triage` instead. Nightly-failure-labeled bot issues belong HERE, not there.
- During an in-flight release (labeling churn can confuse milestone tracking).
- When you only want to triage one specific label (just use `gh issue list --label <label>` directly).
- For all-of-backlog Monday sweeps — invoke `/maintenance-monday` instead; it orchestrates this skill alongside the dependabot/tool-update skills with one consolidated approval gate.

## Triage Rules

### Rule 1: Filter scope — exclude only `dependencies`-labeled bot issues

Most `app/github-actions`-authored issues are tool-version trackers handled by `jmo-tool-update-triage`. Skip issues where `author.login == "app/github-actions"` AND the label set includes `dependencies`.

**Include** the remaining `app/github-actions` issues — specifically those labeled `nightly-test-failure`. They go through Rule 2.7 (Nightly-failure classification path), not the manual-issue rules. They are *not* manual issues; the only thing they share with manual issues is the close-via-this-skill habit.

Quick scope cheat sheet:

| Author | Label includes | Routed to |
|--------|----------------|-----------|
| jimmy058910 (or any non-bot) | any | This skill (manual-issue rules) |
| app/github-actions | `dependencies` | `/jmo-tool-update-triage` (skip here) |
| app/github-actions | `nightly-test-failure` | This skill (Rule 2.7) |
| app/github-actions | anything else | Surface as a warning — unexpected bot issue class, manual review |

### Rule 2: Identify ROADMAP-TRACKING issues first (do not close)

An issue is ROADMAP-TRACKING if **any** of these hold:

- Title matches `/ROADMAP #\d+:/` (e.g., `ROADMAP #10: Web UI for Results Exploration`)
- Has a `roadmap`, `phase-1`, `phase-2`, `phase-3`, or `phase-4` label
- Body explicitly references `ROADMAP.md` or a future release phase

ROADMAP-TRACKING issues are **intentionally long-lived**. Age is not a signal of neglect. Do not apply staleness heuristics. Do not recommend closing. Leave them alone; note them in the output for visibility only.

### Rule 2.5: Identify issues with open linked PRs (do not close)

An issue is **non-closeable** if any open PR references it with GitHub closing syntax (`Fixes #N`, `Closes #N`, `Resolves #N`). That PR is an implementation candidate, not a reason to close the issue before merge.

Use the structural `closedByPullRequestsReferences` field rather than a free-text search — GitHub already parses the closing-keyword syntax and exposes the result, eliminating the false-positive class (e.g., `See also #N` won't appear here):

```bash
# Step 1: get all PRs linked via Fixes/Closes/Resolves syntax
linked_prs=$(gh issue view <n> --repo jimmy058910/jmo-security-repo \
  --json closedByPullRequestsReferences \
  --jq '.closedByPullRequestsReferences[].number')

# Step 2: check whether any of them is still open
for pr in $linked_prs; do
  state=$(gh pr view "$pr" --repo jimmy058910/jmo-security-repo --json state --jq .state)
  [[ "$state" == "OPEN" ]] && echo "Linked open PR: #$pr"
done
```

If at least one linked PR is OPEN, mark the issue **LINKED-PR-PENDING** in the plan output (informational; do not close, do not bucket as stale). If all linked PRs are MERGED but the issue is still open, that's a separate signal — GitHub didn't auto-close (cross-repo merge, non-default-branch close, etc.); route those into the IMPLEMENTED-ON-MAIN check at Rule 3 with the merged PR as canonical reference. If all linked PRs are CLOSED (not merged), no protection; fall through to Rule 3.

Apply this rule **before** the actionability classifier in Rule 3. Linked-PR status overrides staleness — an actively-being-fixed issue is not stale even if 90+ days old. (Borrowed from Clawsweeper's `linked open PRs` non-closeable rule; see [[reference_clawsweeper-issue-triage-patterns]].)

### Rule 2.7: Nightly-failure classification path (separate from manual-issue Rule 3)

This rule applies **only** to `app/github-actions`-authored issues labeled `nightly-test-failure`. Manual issues skip it entirely and proceed to Rule 3.

Each nightly-failure issue represents one failed `scheduled.yml` workflow run. The body is templated (workflow-run URL + generic troubleshooting steps), so classification depends on **external evidence**, not issue content:

1. **Is the failure covered by a later release fix?** (release-tag heuristic)
2. **Did a subsequent nightly run go green?** (workflow-run heuristic)
3. **How recent is the failure?** (age heuristic)

Resolve in this order; first match wins.

#### Sub-action a: BULK-CLOSE-PRE-FIX

A nightly failure dated **before** a release that explicitly addressed nightly stability is presumptively root-caused by that release. Common indicators in CHANGELOG.md or release notes: "CI install hardening", "download hardening", "scheduled workflow", "nightly", `--maxfail` adjustments, `pytest-timeout` fixes, branch coverage merge.

```bash
# Identify the most recent release tag whose body mentions nightly/CI/scheduled
gh release list --repo jimmy058910/jmo-security-repo --limit 10 \
  --json tagName,publishedAt,body \
  --jq '.[] | select(.body | test("nightly|scheduled|CI install|--maxfail"; "i")) | {tag: .tagName, date: .publishedAt[0:10]}' \
  | head -1
```

If `issue.createdAt < release.publishedAt` for the matched tag, classify as **BULK-CLOSE-PRE-FIX**. The close comment is identical across the batch (the release link is the citation), so all items in this sub-action close with one templated message.

#### Sub-action b: SUPERSEDED-BY-GREEN

If a subsequent `scheduled.yml` run completed successfully after the failure date, the original failure was a flake or got fixed incidentally.

```bash
# Find the next successful scheduled.yml run after the issue's failure date
issue_date=$(gh issue view <number> --repo jimmy058910/jmo-security-repo \
  --json createdAt --jq '.createdAt[0:10]')
gh run list --repo jimmy058910/jmo-security-repo \
  --workflow scheduled.yml --status success --limit 5 \
  --created ">${issue_date}" \
  --json databaseId,createdAt,conclusion --jq '.[0]'
```

If a green run exists, classify as **SUPERSEDED-BY-GREEN**. Close as `not planned` with a comment linking the green run.

#### Sub-action c: RECENT-LEAVE-OPEN

If `issue.createdAt` is within the last 7 days AND neither (a) nor (b) applies, leave the issue open. Recent failures may still be actionable; closing them prematurely loses signal. The 7-day window matches the project's "next maintenance pass" cadence — they'll be re-triaged then.

#### Sub-action d: INVESTIGATE-MANUAL

Older than 7 days, no covering release, no superseding green. These are the genuinely uncertain ones — possibly a real persistent bug, possibly a flake whose fix was bundled into an unrelated PR. Surface to the user as a **judgment call** in the plan output. Do not auto-close; the user picks per-item.

#### Sub-action priority and recovery

The first matching sub-action wins. If two could apply (e.g., a pre-fix issue that also has a superseding green), prefer **BULK-CLOSE-PRE-FIX** because its close comment is more informative (cites the actual root cause, not just "a later nightly went green").

If `gh run list` fails (network, rate limit), all candidates fall through to **INVESTIGATE-MANUAL** rather than silently misclassifying. Better a slightly larger judgment-call bucket than wrong-bucket closes.

#### Why this is a separate rule

Nightly-failure trackers are mechanically uniform — same body, same author, varying only by date and workflow run. The classification signal comes from outside the issue (release tags, workflow run history), not the issue itself. Mixing them into Rule 3's actionability table would either force noise into manual classification or hide the rule behind branching logic. Keeping Rule 2.7 separate keeps Rule 3 simple and makes the nightly-batch closure pattern reviewable as one block.

### Rule 3: Classify remaining issues by actionability

For each non-ROADMAP, non-LINKED-PR-PENDING issue, apply in order:

| Check | Outcome |
|-------|---------|
| A newer open issue covers the same bug/feature | DUPLICATE/SUPERSEDED |
| Bug issue has: clear steps to reproduce, expected vs actual behavior, version info | READY-TO-WORK |
| Enhancement issue has: problem statement, proposed solution or acceptance criteria | READY-TO-WORK |
| Bug missing repro steps OR enhancement missing problem statement | NEEDS-INFO |
| `updatedAt` is 90+ days ago AND not ROADMAP AND not recently commented | **Run the IMPLEMENTED-ON-MAIN gate below** → IMPLEMENTED-ON-MAIN if hit, STALE-NEGLECTED if miss |

**IMPLEMENTED-ON-MAIN gate** (mandatory sub-step before any STALE-NEGLECTED close on a bug issue; not a separate first-class path — the only way to reach IMPLEMENTED-ON-MAIN is via the stale gate). For each issue that would otherwise be STALE-NEGLECTED, run a merged-PR search for the issue's keywords:

```bash
gh pr list --repo jimmy058910/jmo-security-repo --state merged \
  --search "<key-terms-from-issue-title>" \
  --json number,title,mergedAt,body --limit 10
```

If a candidate PR exists, verify it actually addresses the report. Cheap proxies (one is enough; use the first that works):

- PR title or body literally references the issue number
- PR's diff touches files mentioned in the bug report
- `git log -S '<bug-specific-string-from-the-report>' --oneline` shows the fix landed since the report was filed

**Outcome routing:**

- **Verified hit** → classify as IMPLEMENTED-ON-MAIN with the PR number as canonical reference; close with `--reason "completed"` + acknowledgment comment.
- **Plausible but unverifiable** (candidate PR exists but title/diff don't conclusively match) → classify as STALE-NEGLECTED but mention the candidate PR in the close comment so the reporter can verify themselves: "Possibly resolved by #N; if so, please reopen and we'll convert to a fix-acknowledgment close."
- **Miss** (no candidate PR found) → classify as STALE-NEGLECTED with the standard inactivity comment.

**Why a gate, not a first-class check:** at solo-dev scale the high-value case is "bug silently fixed long ago, now would otherwise be wontfix'd." A recently-fixed bug filed 30 days ago has clear repro info and routes to READY-TO-WORK; the user closes it manually when merging the fix. Running the merged-PR search on every issue every pass is unnecessary work at our scale. (Clawsweeper runs `implemented_on_main` as a first-class check across every issue every pass; their scale and continuous cadence make that the right call — ours doesn't. See [[reference_clawsweeper-issue-triage-patterns]].)

When in doubt between NEEDS-INFO and STALE-NEGLECTED: if the issue author is `jimmy058910` (the solo dev), prefer STALE-NEGLECTED over NEEDS-INFO — the author already knows the context, so missing details = the issue was deprioritized, not misunderstood.

### Rule 4: `good first issue` candidate check

After classifying a READY-TO-WORK issue, evaluate whether it qualifies for `good first issue`:

- Scope is bounded to a single file or module
- Requires no architectural decisions
- Has clear acceptance criteria
- Does not require deep domain knowledge of the security scanner ecosystem

Only add this label if the issue genuinely fits. The repo currently has 3 `good first issue` labels — quality over quantity; false `good first issue` labels harm contributor trust.

### Rule 5: DUPLICATE/SUPERSEDED requires a canonical OPEN issue

**Scope:** Rule 5 covers the case where another **open** issue tracks the same work. Never close a duplicate without identifying the surviving canonical issue number. If two duplicates exist and neither is clearly canonical, pick the older one as canonical (lower issue number) and close the newer.

For the **already-resolved-by-a-merged-PR** case (a different scenario), use the IMPLEMENTED-ON-MAIN gate inside Rule 3 instead — the close-reason there is `completed` (purple ✓) with a fix acknowledgment, not `not planned` (grey ✕). Routing fixed bugs through Rule 5 would understate the resolution and read as a dismissal.

## Workflow Steps

### Step 1: Discovery (read-only, automatic)

The Live Context block executes at invocation. Verify it returned data:

```bash
gh auth status || { echo "ERROR: gh not authenticated; run gh auth login"; exit 1; }
```

Compute staleness dates at runtime:

```bash
# 90-day cutoff for STALE-NEGLECTED
python3 -c "import datetime; print((datetime.datetime.utcnow() - datetime.timedelta(days=90)).strftime('%Y-%m-%d'))"
```

### Step 2: Build the classification table

For every covered issue (manual + nightly-failure), assign a bucket. Nightly-failure entries include the sub-action in the Action column (BULK-CLOSE-PRE-FIX / SUPERSEDED-BY-GREEN / RECENT-LEAVE-OPEN / INVESTIGATE-MANUAL).

```text
| Issue # | Title                              | Labels                            | Last Activity | Bucket                  | Action                                      |
|---------|------------------------------------|-----------------------------------|---------------|-------------------------|---------------------------------------------|
| #38     | ROADMAP #10: Web UI for Results    | roadmap                           | 188d ago      | ROADMAP-TRACKING        | Leave alone                                 |
| #418    | Add JSON output for jmo diff       | enhancement                       | 100d ago      | LINKED-PR-PENDING       | Leave alone — PR #426 has `Fixes #418`      |
| #388    | tech-debt: bump express 4→5        | technical-debt                    | 7d ago        | READY-TO-WORK           | Label good-first-issue? No                  |
| #412    | Missing --output flag on jmo diff  | bug                               | 3d ago        | NEEDS-INFO              | Comment requesting repro + version          |
| #267    | Dashboard crashes on empty DB      | bug                               | 110d ago      | IMPLEMENTED-ON-MAIN     | Close acknowledging fix in merged #312      |
| #291    | Unused variable in scan.py         | bug                               | 120d ago      | STALE-NEGLECTED         | Close wontfix, no merged PR resolves it     |
| #305    | Support SARIF output               | enhancement                       | 95d ago       | DUPLICATE/SUPERSEDED    | Close, canonical is open issue #311         |
| #275    | Nightly test suite failed on 4-13  | bug, ci, nightly-test-failure     | 40d ago       | NIGHTLY-FAILURE-TRACKER | BULK-CLOSE-PRE-FIX — covered by v1.0.5      |
| #486    | Nightly test suite failed on 5-20  | bug, ci, nightly-test-failure     | 3d ago        | NIGHTLY-FAILURE-TRACKER | RECENT-LEAVE-OPEN — within 7-day window     |
| #421    | Nightly test suite failed on 5-07  | bug, ci, nightly-test-failure     | 16d ago       | NIGHTLY-FAILURE-TRACKER | SUPERSEDED-BY-GREEN — run 26198xxx success  |
| #381    | Nightly test suite failed on 5-02  | bug, ci, nightly-test-failure     | 21d ago       | NIGHTLY-FAILURE-TRACKER | INVESTIGATE-MANUAL — judgment call          |
```

### Step 3: Build the action summary

Counts by bucket and list concrete actions:

```text
ROADMAP-TRACKING       : N issues — leave alone (listed for visibility)
LINKED-PR-PENDING      : N issues — leave alone (open PR is implementing it)
READY-TO-WORK          : N issues — optionally add good-first-issue label
NEEDS-INFO             : N issues — post comment requesting info
IMPLEMENTED-ON-MAIN    : N issues — close with "fixed in #PR" acknowledgment
DUPLICATE/SUPERSEDED   : N issues — close pointing at canonical OPEN issue
STALE-NEGLECTED        : N issues — close with wontfix + comment
NIGHTLY-FAILURE-TRACKER: N issues
  ├── BULK-CLOSE-PRE-FIX  : N — close as completed referencing release tag
  ├── SUPERSEDED-BY-GREEN : N — close as not planned linking the green run
  ├── RECENT-LEAVE-OPEN   : N — leave open (within 7-day window)
  └── INVESTIGATE-MANUAL  : N — judgment call, await user decision
```

### Step 4: Present the plan (REQUIRED — do not skip)

```text
## Issue Triage Plan (N manual issues + M nightly-failure trackers, YYYY-MM-DD)

### ROADMAP-TRACKING — leave alone (N)
- #38 ROADMAP #10: Web UI ... (188d, roadmap label) — intentional placeholder
- #37 GitHub App Integration (190d, roadmap label) — intentional placeholder

### LINKED-PR-PENDING — leave alone (N)
- #418 Add JSON output for jmo diff — PR #426 has `Fixes #418`, currently open

### READY-TO-WORK — no action or label (N)
- #388 tech-debt: bump express 4→5 — scope clear, actionable
- #391 Improve error message on missing jmo.yml — good first issue candidate

### NEEDS-INFO — will comment (N)
- #412 Missing --output flag — will ask for: repro command, jmo version, OS

### IMPLEMENTED-ON-MAIN — will close acknowledging fix (N)
- #267 Dashboard crashes on empty DB — verified fixed by merged PR #312
  - Evidence: PR #312 touches `dashboard/empty_state.tsx`; commit landed 2026-03-15 (after issue filed 2026-01-02)
  - Close comment will credit reporter and link the fix

### DUPLICATE/SUPERSEDED — will close (N)
- #305 Support SARIF output — duplicate of open issue #311

### STALE-NEGLECTED — will close wontfix (N)
- #291 Unused variable in scan.py — 120d no activity, deprioritized, no merged PR resolves

### NIGHTLY-FAILURE-TRACKER — sub-action breakdown (M total)

#### BULK-CLOSE-PRE-FIX — will close as completed (P)
Covered by release v1.0.5 (published 2026-04-28; release notes cite "CI install hardening").
All N issues dated before that release date close with one templated comment.
- #236 (4-03), #261 (4-04), ..., #342 (4-26) — 24 issues, close batch

#### SUPERSEDED-BY-GREEN — will close as not planned (Q)
- #421 (5-07) — superseded by green run #26198xxxxx on 2026-05-08

#### RECENT-LEAVE-OPEN — leave open (R)
- #492 (today) — within 7-day window; re-evaluate next pass
- #486 (3d ago) — within 7-day window; re-evaluate next pass

#### INVESTIGATE-MANUAL — judgment call (S)
- #381 (5-02) — older than 7d but no covering release, no superseding green. Investigate or accept stale close.

Approve to execute, or list specific items to skip.
```

**Stop and wait for user confirmation.** Do not proceed to Step 5 in `--dry-run` mode (default).

### Step 5: Execute (only with explicit `--execute` flag)

In order (happiest closes first, wontfix last; labels at the end):

```bash
# 5a: Post NEEDS-INFO comments (gather info before any closes)
gh issue comment <number> --repo jimmy058910/jmo-security-repo \
  --body "Thanks for filing this. To help reproduce the issue, could you share:
- Exact command you ran (with flags)
- \`jmo --version\` output
- OS and Python version
- Any relevant error output or stack trace"

# 5b: Close IMPLEMENTED-ON-MAIN (credits the reporter; --reason "completed")
gh issue close <number> --repo jimmy058910/jmo-security-repo \
  --reason "completed" \
  --comment "Closing — this was fixed by #<pr-number> (merged <yyyy-mm-dd>). Thanks for the report. If you still hit the original symptom on a current release, please reopen with version info and we'll dig back in."

# 5c: Close DUPLICATE/SUPERSEDED (canonical must be OPEN)
gh issue close <number> --repo jimmy058910/jmo-security-repo \
  --reason "not planned" \
  --comment "Closing as duplicate of #<canonical>. Tracking there."

# 5d: Close STALE-NEGLECTED
gh issue close <number> --repo jimmy058910/jmo-security-repo \
  --reason "not planned" \
  --comment "Closing due to inactivity (90+ days). If this is still relevant, please reopen with updated context."

# 5e: Add good-first-issue label to qualifying READY-TO-WORK issues
gh issue edit <number> --repo jimmy058910/jmo-security-repo \
  --add-label "good first issue"

# 5f: Close NIGHTLY-FAILURE-TRACKER BULK-CLOSE-PRE-FIX batch (one comment template per batch; release link is the citation)
gh issue close <number> --repo jimmy058910/jmo-security-repo \
  --reason "completed" \
  --comment "Closing — this nightly failure predates release <tag> (published <yyyy-mm-dd>), which addressed the root cause (see release notes for CI install hardening + scheduled-workflow stability fixes). Subsequent nightlies have run clean. If a similar failure recurs on a current release, please reopen with the new workflow-run link."

# 5g: Close NIGHTLY-FAILURE-TRACKER SUPERSEDED-BY-GREEN (per-item; cite the green run)
gh issue close <number> --repo jimmy058910/jmo-security-repo \
  --reason "not planned" \
  --comment "Closing — a subsequent scheduled.yml run completed successfully (<green-run-url>), so the original failure was flake-class or got incidentally fixed. Reopen if it recurs."
```

**Reason-code note**: `--reason "completed"` (for IMPLEMENTED-ON-MAIN and NIGHTLY BULK-CLOSE-PRE-FIX) renders as a purple ✓ on GitHub; `--reason "not planned"` renders as a grey ✕. Using the right reason matters for backlog statistics and reporter sentiment — a fixed bug closed as "not planned" reads as a dismissal. The pre-fix bucket uses `completed` because the failure WAS fixed (just by a release-wide change, not a single PR).

**Nightly batch ergonomics**: 5f closes can be wrapped in a small shell loop since the comment template is identical and only the issue number varies. Keep the loop sequential (not parallel) — `gh` doesn't deduplicate concurrent writes and you want a clean per-item failure mode if rate limits hit:

```bash
for n in 236 261 263 264 265 267 269 270 272 274 275 277 278 289 290 294 299 312 319 325 329 337 338 342; do
  gh issue close "$n" --repo jimmy058910/jmo-security-repo \
    --reason "completed" \
    --comment "Closing — this nightly failure predates release v1.0.5 (published 2026-04-28), which addressed the root cause..." \
    || { echo "Failed on #$n"; break; }
  sleep 0.5
done
```

### Step 6: Verification

After execution, re-run the Live Context queries and confirm:

- NEEDS-INFO issues have a comment requesting reproduction details
- IMPLEMENTED-ON-MAIN issues are closed with `--reason "completed"` and link the fix PR
- DUPLICATE/SUPERSEDED and STALE-NEGLECTED issues are closed with `--reason "not planned"`
- NIGHTLY-FAILURE-TRACKER BULK-CLOSE-PRE-FIX issues are closed with `--reason "completed"` and cite the release tag
- NIGHTLY-FAILURE-TRACKER SUPERSEDED-BY-GREEN issues are closed with `--reason "not planned"` and link the green run
- NIGHTLY-FAILURE-TRACKER RECENT-LEAVE-OPEN and INVESTIGATE-MANUAL issues are untouched
- READY-TO-WORK issues have `good first issue` label where appropriate
- ROADMAP-TRACKING and LINKED-PR-PENDING issues are untouched

Also confirm the nightly backlog dropped by the expected count: `gh issue list --label nightly-test-failure --state open --json number --jq length` should equal `(open before) - (BULK-CLOSE-PRE-FIX + SUPERSEDED-BY-GREEN count)`. If the count is wrong, a silent `gh issue close` failure happened mid-loop.

## Failure Modes

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| `gh issue list` returns empty | `gh` unauthenticated or wrong repo slug | `gh auth status`; verify `jimmy058910/jmo-security-repo` |
| `gh issue close --reason "not planned"` fails | `gh` CLI version < 2.32 lacks `--reason` flag | `gh issue close <n> --comment "..."` without `--reason`; upgrade gh |
| `gh issue close --reason "completed"` fails | `gh` CLI version < 2.45 lacks `completed` as a valid value | Upgrade gh (`gh --version` to check); fallback: omit `--reason` and use `--comment` only — but mention in the comment that this was closed as fixed, not wontfix |
| IMPLEMENTED-ON-MAIN check returns a candidate PR but you're not sure it actually fixes the report | Title-keyword match is loose; the PR may be tangentially related | Demote to STALE-NEGLECTED but include the candidate PR number in the close comment: "Possibly resolved by #N; if so, reopen and we'll convert to a fix-acknowledgment close." Lets the reporter verify. |
| Linked-PR query returns false positives (PR mentions issue number in non-closing context, e.g., `See also #N`) | GitHub `gh pr list --search` matches keywords anywhere in body | Inspect the matched PR's body manually for explicit `Fixes/Closes/Resolves` syntax before classifying as LINKED-PR-PENDING; if the reference is non-binding, fall through to normal classification |
| ROADMAP issue misclassified as stale | Staleness heuristic applied before ROADMAP check | Always run Rule 2 (ROADMAP filter) before Rule 3 (staleness); ROADMAP wins |
| Label `good first issue` doesn't exist | Label not yet created in repo | `gh label create "good first issue" --color "7057ff" --repo jimmy058910/jmo-security-repo` |
| `app/github-actions` issues with label other than `dependencies` or `nightly-test-failure` | New bot-authored issue class introduced (e.g., security advisory, dependency review) | Surface to user; do not classify silently. Decide whether to add a new sub-rule or delegate to a new sibling skill. Update Rule 1 cheat sheet once routed. |
| Nightly-failure release-tag heuristic returns nothing | No recent release notes mention `nightly`/`scheduled`/`CI install`/`--maxfail` | Fall through to SUPERSEDED-BY-GREEN check; if that also misses, route to INVESTIGATE-MANUAL. Do not auto-assume any release covers nightly stability. |
| `gh run list --workflow scheduled.yml` returns empty | Workflow renamed, or filter syntax `--status success --created ">date"` not honored | Re-check `.github/workflows/` for current workflow file name. Verify `gh --version >= 2.45` (older versions don't parse `--created ">date"`). Fall through to INVESTIGATE-MANUAL on persistent failure. |
| Bulk-close shell loop fails halfway | `gh` rate limit hit, or one issue was closed by another process between dry-run and execute | The `&#124;&#124; break` (bash-OR-on-failure) construct in the loop catches it; resume by editing the remaining issue numbers into a new loop. Do NOT use `parallel` or `xargs -P` — sequential is intentional. |
| Closed issue re-opened by author | Author disagrees with staleness close | Treat re-open as signal the issue IS still active; reclassify to NEEDS-INFO |
| `gh issue comment` 422 on closed issue | Issue was closed between discovery and execution | Skip; already handled |

## Examples

### Routine monthly sweep

```text
/jmo-issue-triage
```

Defaults to dry-run. Reviews all manual issues, presents classification table and plan, waits for approval.

### Execute a previously-reviewed plan

```text
/jmo-issue-triage --execute
```

Re-runs discovery (in case state changed since the dry run), shows plan one more time, executes on user confirmation.

### Pre-release backlog check

Run before opening a new milestone for `v1.0.6`:

```text
/jmo-issue-triage
```

If the plan surfaces actionable READY-TO-WORK bugs relevant to the milestone, assign them. ROADMAP-TRACKING issues remain in the backlog as future-phase candidates.

## Project Policy Encoded

- **No stale-bot** — solo-dev longevity bias ([feedback memory](../../../memory/feedback_solo-dev-longevity-bias.md)): no automated infra for issue hygiene; this skill is the cadence. Run it manually.
- **ROADMAP issues are not stale** — long-lived placeholders for future phases are intentional. Age is not a closing signal. Never auto-close them.
- **Linked PRs are non-closeable** — any issue referenced by an open PR with `Fixes/Closes/Resolves #N` syntax stays open until the PR merges or closes. The PR is the implementation candidate; closing the issue prematurely creates a stale tag in the merged-PR history. (Rule 2.5.)
- **Verify before STALE-NEGLECTED close** — for bug issues, always run a merged-PR keyword search before closing as stale (Rule 3 IMPLEMENTED-ON-MAIN check). A reporter whose bug was silently fixed by an unrelated refactor deserves a "fixed in #N" acknowledgment closed as `--reason "completed"`, not a `wontfix`.
- **Every close has a reason** — all `gh issue close` calls must include `--reason` and `--comment`. Future audits depend on this. Use `--reason "completed"` for IMPLEMENTED-ON-MAIN and NIGHTLY BULK-CLOSE-PRE-FIX; `--reason "not planned"` for everything else.
- **NEEDS-INFO before close** — bugs missing repro data get a comment first; if they go 90+ days with no response after that comment, they become STALE-NEGLECTED on the next triage pass.
- **Conservative `good first issue` labeling** — only label issues that a new contributor can genuinely pick up without deep context. Quality over quantity; the repo intentionally keeps this count small.
- **Nightly trackers must cite evidence** — every NIGHTLY-FAILURE-TRACKER close comment links either a release tag (BULK-CLOSE-PRE-FIX) or a green workflow run URL (SUPERSEDED-BY-GREEN). Closing a nightly tracker with just "stale" is not acceptable — the bot will recreate it next time the underlying issue recurs, and a closure with no evidence trail leaves no breadcrumb.
- **Nightly recency window is 7 days** — failures within the last 7 days stay open regardless of release coverage. The window matches the project's "next maintenance pass" cadence so recent failures get human eyes before mechanical closure.
- **No bulk closes** — even in `--execute` mode, review the plan before approving. Closing issues creates notification noise for watchers and is hard to reverse cleanly. The single exception is the NIGHTLY BULK-CLOSE-PRE-FIX batch, which is explicitly bulk-by-design — a single root cause covers all entries and one templated comment fits all. Even there, the plan lists every issue number for approval before the loop runs.

## See Also

- `.claude/skills/jmo-dependabot-triage/SKILL.md` — handles Dependabot PRs and GH security alerts (separate scope)
- `.claude/skills/jmo-tool-update-triage/SKILL.md` — handles `app/github-actions` issues labeled `dependencies` (tool-version update trackers); do not mix with this skill's scope
- `.claude/skills/maintenance-monday/SKILL.md` — orchestrator that runs this skill + dependabot-triage + tool-update-triage in one consolidated pass
- `.claude/skills/merge-pr/SKILL.md` — used if a READY-TO-WORK fix is implemented and needs a PR shipped
- `.claude/skills/jmo-ci-debugger/SKILL.md` — invoke if an INVESTIGATE-MANUAL nightly tracker turns out to be a real persistent bug
- [`feedback_solo-dev-longevity-bias.md`](../../../memory/feedback_solo-dev-longevity-bias.md) — project policy on avoiding automation overhead
- `ROADMAP.md` — canonical source for ROADMAP-TRACKING issue content; cross-check issue body against it
