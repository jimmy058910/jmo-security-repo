---
name: jmo-issue-triage
description: >
  Periodic sweep of general open issues (bug, enhancement, technical-debt,
  documentation). Classifies every manual issue into one of five buckets —
  READY-TO-WORK, NEEDS-INFO, ROADMAP-TRACKING, STALE-NEGLECTED,
  DUPLICATE/SUPERSEDED — and produces a plan-mode review with explicit
  per-item recommendations. Designed for monthly cadence; does NOT touch
  Dependabot PRs (jmo-dependabot-triage) or tool-version update issues
  from app/github-actions (jmo-tool-update-triage).
argument-hint: "[--dry-run | --execute] (default: dry-run, plan mode only)"
user-invocable: true
context: fork
allowed-tools: Bash, Read, Grep, Edit, Write
---

## Live Context

**All open issues NOT authored by app/github-actions (manual issues only):**
!gh issue list --repo jimmy058910/jmo-security-repo --state open --limit 100 --search "-author:app/github-actions" --json number,title,labels,createdAt,updatedAt,author,body,comments 2>/dev/null

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

Periodically (monthly cadence recommended) sweep the manual issue backlog so actionable bugs don't stall and intentional ROADMAP placeholders aren't misidentified as neglect. Produces a structured plan classifying every open manual issue into one of five buckets:

1. **READY-TO-WORK** — clear scope, has reproduction (bugs) or problem statement (enhancements); candidate for `good first issue` if scoped small enough
2. **NEEDS-INFO** — bug missing reproduction steps or enhancement missing problem statement; comment to gather info, do NOT close
3. **ROADMAP-TRACKING** — intentional long-lived placeholder for `ROADMAP.md` items (issues with `roadmap` or `phase-*` labels, or titles matching `ROADMAP #N:` pattern); leave alone, NOT stale
4. **STALE-NEGLECTED** — non-roadmap issue with no activity for 90+ days, unlikely to be actioned; close with `wontfix` reason + explanation comment
5. **DUPLICATE/SUPERSEDED** — covered by another open issue or already resolved in a merged PR; close pointing at the canonical issue

The skill **never executes destructive actions without user approval**. It enters plan mode by default.

## When to Use

- Monthly cadence or before a new minor release cycle to ensure the backlog reflects current priorities.
- When the open issue count "feels wrong" (rule of thumb: >15 manual issues with no recent triage pass).
- Before creating a roadmap or milestone to understand what's already tracked.
- When a new contributor asks "what can I work on?" — triage first, then point at READY-TO-WORK issues.

## When NOT to Use

- For Dependabot PRs or GH security alerts — use `/jmo-dependabot-triage` instead.
- For the ~47 `app/github-actions` tool-version update issues (`Update <tool> to vX.Y.Z`) — use `/jmo-tool-update-triage` instead.
- During an in-flight release (labeling churn can confuse milestone tracking).
- When you only want to triage one specific label (just use `gh issue list --label <label>` directly).

## Triage Rules

### Rule 1: Filter scope — exclude app/github-actions issues

All `app/github-actions`-authored issues are tool-version trackers. They are handled exclusively by `jmo-tool-update-triage`. Skip any issue where `author.login == "app/github-actions"`.

### Rule 2: Identify ROADMAP-TRACKING issues first (do not close)

An issue is ROADMAP-TRACKING if **any** of these hold:

- Title matches `/ROADMAP #\d+:/` (e.g., `ROADMAP #10: Web UI for Results Exploration`)
- Has a `roadmap`, `phase-1`, `phase-2`, `phase-3`, or `phase-4` label
- Body explicitly references `ROADMAP.md` or a future release phase

ROADMAP-TRACKING issues are **intentionally long-lived**. Age is not a signal of neglect. Do not apply staleness heuristics. Do not recommend closing. Leave them alone; note them in the output for visibility only.

### Rule 3: Classify remaining issues by actionability

For each non-ROADMAP issue, apply in order:

| Check | Outcome |
|-------|---------|
| A newer open issue covers the same bug/feature | DUPLICATE/SUPERSEDED |
| Bug issue has: clear steps to reproduce, expected vs actual behavior, version info | READY-TO-WORK |
| Enhancement issue has: problem statement, proposed solution or acceptance criteria | READY-TO-WORK |
| Bug missing repro steps OR enhancement missing problem statement | NEEDS-INFO |
| `updatedAt` is 90+ days ago AND not ROADMAP AND not recently commented | STALE-NEGLECTED |

When in doubt between NEEDS-INFO and STALE-NEGLECTED: if the issue author is `jimmy058910` (the solo dev), prefer STALE-NEGLECTED over NEEDS-INFO — the author already knows the context, so missing details = the issue was deprioritized, not misunderstood.

### Rule 4: `good first issue` candidate check

After classifying a READY-TO-WORK issue, evaluate whether it qualifies for `good first issue`:

- Scope is bounded to a single file or module
- Requires no architectural decisions
- Has clear acceptance criteria
- Does not require deep domain knowledge of the security scanner ecosystem

Only add this label if the issue genuinely fits. The repo currently has 3 `good first issue` labels — quality over quantity; false `good first issue` labels harm contributor trust.

### Rule 5: DUPLICATE/SUPERSEDED requires a canonical target

Never close a duplicate without identifying the surviving canonical issue number. If two duplicates exist and neither is clearly canonical, pick the older one as canonical (lower issue number) and close the newer.

Check merged PRs when an issue might already be resolved:

```bash
gh pr list --repo jimmy058910/jmo-security-repo --state merged --search "<keyword>" --json number,title,mergedAt --limit 10
```

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

For every manual issue, assign a bucket:

```text
| Issue # | Title                              | Labels                  | Last Activity | Bucket                | Action                              |
|---------|------------------------------------|-------------------------|---------------|-----------------------|-------------------------------------|
| #38     | ROADMAP #10: Web UI for Results    | roadmap                 | 188d ago      | ROADMAP-TRACKING      | Leave alone                         |
| #37     | GitHub App Integration             | roadmap, enhancement    | 190d ago      | ROADMAP-TRACKING      | Leave alone                         |
| #34     | Plugin System                      | roadmap, phase-3        | 195d ago      | ROADMAP-TRACKING      | Leave alone                         |
| #388    | tech-debt: bump express 4→5        | technical-debt          | 7d ago        | READY-TO-WORK         | Label good-first-issue? No          |
| #412    | Missing --output flag on jmo diff  | bug                     | 3d ago        | NEEDS-INFO            | Comment requesting repro + version  |
| #291    | Unused variable in scan.py         | bug                     | 120d ago      | STALE-NEGLECTED       | Close wontfix, no recent activity   |
| #305    | Support SARIF output               | enhancement             | 95d ago       | DUPLICATE/SUPERSEDED  | Close, canonical is #311            |
```

### Step 3: Build the action summary

Counts by bucket and list concrete actions:

```text
ROADMAP-TRACKING  : N issues — leave alone (listed for visibility)
READY-TO-WORK     : N issues — optionally add good-first-issue label
NEEDS-INFO        : N issues — post comment requesting info
STALE-NEGLECTED   : N issues — close with wontfix + comment
DUPLICATE/SUPERSEDED: N issues — close with comment pointing at canonical
```

### Step 4: Present the plan (REQUIRED — do not skip)

```text
## Issue Triage Plan (N manual issues, YYYY-MM-DD)

### ROADMAP-TRACKING — leave alone (N)
- #38 ROADMAP #10: Web UI ... (188d, roadmap label) — intentional placeholder
- #37 GitHub App Integration (190d, roadmap label) — intentional placeholder

### READY-TO-WORK — no action or label (N)
- #388 tech-debt: bump express 4→5 — scope clear, actionable
- #391 Improve error message on missing jmo.yml — good first issue candidate

### NEEDS-INFO — will comment (N)
- #412 Missing --output flag — will ask for: repro command, jmo version, OS

### STALE-NEGLECTED — will close wontfix (N)
- #291 Unused variable in scan.py — 120d no activity, deprioritized

### DUPLICATE/SUPERSEDED — will close (N)
- #305 Support SARIF output — duplicate of #311

Approve to execute, or list specific items to skip.
```

**Stop and wait for user confirmation.** Do not proceed to Step 5 in `--dry-run` mode (default).

### Step 5: Execute (only with explicit `--execute` flag)

In order:

```bash
# 5a: Post NEEDS-INFO comments (gather info before any closes)
gh issue comment <number> --repo jimmy058910/jmo-security-repo \
  --body "Thanks for filing this. To help reproduce the issue, could you share:
- Exact command you ran (with flags)
- \`jmo --version\` output
- OS and Python version
- Any relevant error output or stack trace"

# 5b: Close DUPLICATE/SUPERSEDED
gh issue close <number> --repo jimmy058910/jmo-security-repo \
  --reason "not planned" \
  --comment "Closing as duplicate of #<canonical>. Tracking there."

# 5c: Close STALE-NEGLECTED
gh issue close <number> --repo jimmy058910/jmo-security-repo \
  --reason "not planned" \
  --comment "Closing due to inactivity (90+ days). If this is still relevant, please reopen with updated context."

# 5d: Add good-first-issue label to qualifying READY-TO-WORK issues
gh issue edit <number> --repo jimmy058910/jmo-security-repo \
  --add-label "good first issue"
```

### Step 6: Verification

After execution, re-run the Live Context queries and confirm:

- NEEDS-INFO issues have a comment requesting reproduction details
- STALE-NEGLECTED and DUPLICATE issues are closed with reasons
- READY-TO-WORK issues have `good first issue` label where appropriate
- ROADMAP-TRACKING issues are untouched

## Failure Modes

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| `gh issue list` returns empty | `gh` unauthenticated or wrong repo slug | `gh auth status`; verify `jimmy058910/jmo-security-repo` |
| `gh issue close --reason "not planned"` fails | `gh` CLI version < 2.32 lacks `--reason` flag | `gh issue close <n> --comment "..."` without `--reason`; upgrade gh |
| ROADMAP issue misclassified as stale | Staleness heuristic applied before ROADMAP check | Always run Rule 2 (ROADMAP filter) before Rule 3 (staleness); ROADMAP wins |
| Label `good first issue` doesn't exist | Label not yet created in repo | `gh label create "good first issue" --color "7057ff" --repo jimmy058910/jmo-security-repo` |
| `app/github-actions` issues appearing in results | `--search "-author:app/github-actions"` not filtering correctly | Use explicit `--author jimmy058910` filter instead |
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
- **Every close has a reason** — all `gh issue close` calls must include `--reason` and `--comment`. Future audits depend on this.
- **NEEDS-INFO before close** — bugs missing repro data get a comment first; if they go 90+ days with no response after that comment, they become STALE-NEGLECTED on the next triage pass.
- **Conservative `good first issue` labeling** — only label issues that a new contributor can genuinely pick up without deep context. Quality over quantity; the repo intentionally keeps this count small.
- **No bulk closes** — even in `--execute` mode, review the plan before approving. Closing issues creates notification noise for watchers and is hard to reverse cleanly.

## See Also

- `.claude/skills/jmo-dependabot-triage/SKILL.md` — handles Dependabot PRs and GH security alerts (separate scope)
- `.claude/skills/merge-pr/SKILL.md` — used if a READY-TO-WORK fix is implemented and needs a PR shipped
- `.claude/skills/jmo-ci-debugger/SKILL.md` — invoke if a bug issue references a flaky CI test
- [`feedback_solo-dev-longevity-bias.md`](../../../memory/feedback_solo-dev-longevity-bias.md) — project policy on avoiding automation overhead
- `ROADMAP.md` — canonical source for ROADMAP-TRACKING issue content; cross-check issue body against it
- `jmo-tool-update-triage` (planned skill) — handles the ~47 `app/github-actions` tool-version update issues; do not mix with this skill's scope
