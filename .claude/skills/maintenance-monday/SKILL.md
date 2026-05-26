---
name: maintenance-monday
description: >
  Orchestrate the three triage skills (jmo-issue-triage,
  jmo-dependabot-triage, jmo-tool-update-triage) in dry-run mode PLUS a
  built-in CI-health sweep, and present ONE consolidated plan with a single
  approval gate. On approval, executes each accepted batch in sequence.
  Section D (CI Health) is native to this skill — it detects failing
  scheduled/maintenance cron runs and stuck `app/github-actions` PRs that
  fall in the blind spot between the Dependabot and tool-update child skills,
  so CI never rots silently. Designed for Monday-morning weekly maintenance —
  collapses four concerns into one pass. Use when you want all-of-backlog
  triage plus CI-health in one go rather than four separate checks.
argument-hint: "[--dry-run | --execute] (default: dry-run, plan mode only)"
user-invocable: true
disable-model-invocation: true
context: fork
allowed-tools: Bash, Read, Grep, Edit, Write, Skill
---

## Live Context

**Open manual issues (jmo-issue-triage scope — non `app/github-actions`):**
!gh issue list --repo jimmy058910/jmo-security-repo --state open --search "-author:app/github-actions" --json number --jq length 2>/dev/null

**Open Dependabot PRs (jmo-dependabot-triage scope):**
!gh pr list --repo jimmy058910/jmo-security-repo --state open --search "author:app/dependabot" --json number --jq length 2>/dev/null

**Open Dependabot security alerts:**
!gh api repos/jimmy058910/jmo-security-repo/dependabot/alerts --paginate -q '[.[] | select(.state=="open")] | length' 2>/dev/null

**Open tool-version update issues (jmo-tool-update-triage scope — `app/github-actions`, label `dependencies`):**
!gh issue list --repo jimmy058910/jmo-security-repo --author "app/github-actions" --label dependencies --state open --json number --jq length 2>/dev/null

**Section D — failing maintenance/scheduled cron runs (last 24h):**
!gh run list --repo jimmy058910/jmo-security-repo --workflow=maintenance.yml --status=failure --created "$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)" --json conclusion --jq length 2>/dev/null

**Section D — stuck `app/github-actions` PRs (the blind spot — BLOCKED or needs-review):**
!gh pr list --repo jimmy058910/jmo-security-repo --state open --search "author:app/github-actions" --json number,mergeStateStatus --jq '[.[] | select(.mergeStateStatus=="BLOCKED")] | length' 2>/dev/null

**Current branch (must be `main` for execute):**
!git -C "$PWD" rev-parse --abbrev-ref HEAD

---

## Purpose

Collapse the three weekly/monthly triage skills into a single orchestrated pass. Instead of:

1. Open Claude Code, run `/jmo-dependabot-triage`, sit through discovery, approve plan, execute
2. Open Claude Code, run `/jmo-issue-triage`, sit through discovery, approve plan, execute
3. Open Claude Code, run `/jmo-tool-update-triage`, sit through discovery, approve plan, execute

…you run `/maintenance-monday` once. Discovery happens in parallel (or sequentially with no manual handoff), all three plans are merged into one consolidated review, and you approve/skip per child-skill batch in a single session.

The skill **never executes destructive actions without user approval**. Plan mode by default. The approval gate at the end is a per-child-skill decision, not per-item.

## When to Use

- **Monday morning weekly maintenance window** — the canonical use case. Catches the weekend's Dependabot batch + the Sunday `auto-update-tools` cron output + any manual issues that accumulated.
- **Pre-release backlog sweep** — before tagging `v*`, run this to ensure no actionable bugs / stale Dependabot alerts / outdated tool versions ship with the release.
- **When all three triage skills "feel due"** — rather than running them sequentially with three discoveries.

## When NOT to Use

- **When you only want one of the three** — invoke the child skill directly. This skill always runs all three; there's no `--only-dependabot` flag.
- **During an in-flight release** — labeling churn across three triages confuses milestone tracking.
- **For non-Dependabot dependency PRs (Renovate, manual bumps)** — those have different semantics; the child skills don't cover them and neither does this one.
- **When working tree is dirty on `main`** — child skills may add `overrides` to `package.json` during execute; requires clean base.

## Orchestration Rules

### Rule 1: Children run in dry-run during discovery (always)

Regardless of how `/maintenance-monday` is invoked, the discovery phase invokes each child skill in **dry-run mode** so all three plans can be presented as one consolidated review before any mutations happen. The `--execute` flag on `/maintenance-monday` only affects the execute phase after approval.

### Rule 2: Children run in a stable order

Always discover in this order:

1. `/jmo-issue-triage` (manual issues — touches no PRs, lowest blast radius for discovery)
2. `/jmo-dependabot-triage` (Dependabot PRs + security alerts)
3. `/jmo-tool-update-triage` (`app/github-actions` tool-version issues)
4. **Section D — CI Health** (native to this skill, not a child skill — failing crons + stuck `app/github-actions` PRs)

Execute in the **same order** on approval. This ordering is conservative: issue triage doesn't touch PRs, Dependabot triage may close PRs but doesn't touch tool-version issues, tool-update triage may bump versions that affect future Dependabot PRs, and Section D runs **last** because merging a stuck PR or closing issues in earlier sections can change CI state (e.g. a Section B merge clears a `BLOCKED` rollup). Re-read CI state at execute time, not just discovery time.

### Rule 3: Approval is per-child-skill batch (v1 limitation)

The consolidated plan shows four sections — A/B/C (one per child skill) plus D (CI Health). Approval is per section — you either approve `jmo-dependabot-triage`'s entire batch or skip it entirely. You cannot pick "merge PR #491 and close PR #487 but skip PR #485" from within a single child skill's plan. (Section D is finer in practice: each `STUCK-BOT-PR` admin-merge is a separate `!` command you choose to run or not.)

If you need fine-grained per-item approval, invoke the relevant child skill directly with `--dry-run` and then `--execute` only the items you accept manually. The super-skill is for the common case where each child's plan is acceptable as a batch or rejected as a batch.

### Rule 4: A child skill's failure during execute does not roll back prior children

If `/jmo-dependabot-triage --execute` partially fails (e.g., GitHub API throttle, branch conflict on rebase), `/jmo-issue-triage`'s already-executed changes remain. The super-skill reports the partial failure and the user decides whether to re-run the failed child manually.

This matches the failure model of running the three skills sequentially today. It does NOT introduce atomicity across triages.

### Rule 5: Skip pre-discovery if backlog count is zero

If the Live Context block above shows all counts at 0 (0 manual issues, 0 Dependabot PRs, 0 alerts, 0 tool-update issues, 0 failing crons, 0 stuck bot PRs), report "Backlog clear — no triage needed" and exit. Do not invoke child skills just to confirm they have nothing to do. **Exception:** if only the Section D counts are non-zero (CI is unhealthy but the issue/PR backlog is empty), still proceed — a red cron or a stuck PR is exactly what this skill must never let rot.

### Rule 6: Section D closes the `app/github-actions` PR blind spot

The three child skills have a structural gap: `jmo-dependabot-triage` scopes to `author:app/dependabot` PRs, `jmo-tool-update-triage` scopes to `app/github-actions` *issues* (not PRs), and `jmo-issue-triage` excludes `app/github-actions` entirely. **PRs authored by `app/github-actions` (the weekly `auto-update-deps-*` tool-version bumps) are covered by none of them.** Section D owns that scope.

This blind spot is not hypothetical — it caused a chronic CI failure. On a **personal-account repo**, a PR opened by a workflow's `GITHUB_TOKEN` cannot satisfy a required `quick-checks` status (GitHub recursion-prevention means the check never runs) and the token cannot be granted a ruleset bypass (Integration bypass actors are organization-only — the API returns HTTP 422). Such a PR is permanently `BLOCKED`, the soak-window auto-merge cron can't merge it, and — before the fix — that crashed `maintenance.yml` every 6h. As of the fail-soft fix in `auto_merge_tool_bumps.py`, the cron now flips these to `needs-review` and stays green, but the PR still needs a **maintainer's admin-merge**. Section D surfaces them so that admin-merge happens during the Monday sweep instead of accumulating unseen.

**One-time prerequisite for admin-merge (do this once, then it works forever):** Rulesets do NOT auto-exempt repository admins the way legacy branch protection did. With an empty `bypass_actors` list, even the owner's `gh pr merge --admin` fails with `Repository rule violations found — Required status check "quick-checks" is expected`. To enable admin-merge, add the **Repository admin** role to the ruleset's bypass list once: **Settings → Rules → Rulesets → "Protect main branch (minimal)" → Bypass list → Add bypass → Repository admin → Always** (or via API: `bypass_actors: [{actor_id: 5, actor_type: "RepositoryRole", bypass_mode: "always"}]`). After that, `gh pr merge <n> --squash --admin --delete-branch` works (plain merge still reports "base branch policy prohibits" — you must pass `--admin` to invoke the bypass, even as a bypass actor). This was configured for this repo on 2026-05-26.

## Workflow Steps

### Step 1: Discovery (read-only, sequential)

Invoke each child skill in dry-run mode, in the stable order from Rule 2. Capture each plan's structured output (the bucket summary and action lists from each skill's Step 4 plan section).

Important: do not paste each child's full output into the chat as it runs — that creates ~3× the noise of running them separately. Instead, collect the structured plan sections from each child's output and present them only in Step 2's consolidated view.

For each child skill:

```text
Invoke /jmo-issue-triage in dry-run mode. Capture the Step 4 plan output (the bucket-by-bucket actions).
Invoke /jmo-dependabot-triage in dry-run mode. Capture the Step 4 plan output.
Invoke /jmo-tool-update-triage in dry-run mode. Capture the Step 4 plan output.
```

Then run the **Section D — CI Health** sweep directly (no child skill — these are native `gh` queries):

```bash
# D1. Failing maintenance/scheduled cron runs in the last ~48h.
gh run list --workflow=maintenance.yml --status=failure --limit 10 \
  --json conclusion,createdAt,displayTitle,databaseId,url
gh run list --workflow=scheduled.yml  --status=failure --limit 10 \
  --json conclusion,createdAt,displayTitle,databaseId,url

# D2. Stuck app/github-actions PRs (the blind spot). For each, capture
#     mergeStateStatus + the status rollup so the plan can classify it.
gh pr list --state open --search "author:app/github-actions" \
  --json number,title,mergeStateStatus,labels,statusCheckRollup
```

Classify each Section D finding into one bucket:

| Bucket | Signal | Recommended action |
|--------|--------|--------------------|
| `STUCK-BOT-PR` | `app/github-actions` PR, `mergeStateStatus: BLOCKED`, all *present* rollup checks green | **Maintainer admin-merge** — the cron can't (personal-repo constraint). Surface the exact `! gh pr merge <n> --squash --admin --delete-branch` for the user to run. |
| `FAILING-CRON` | A `maintenance.yml` / `scheduled.yml` run failed and the failure persists on the latest run | Route to `/jmo-ci-debugger`. Do **not** fix workflow/script bugs inline — keep blast radius bounded. |
| `TRANSIENT-FLAKE` | A single failed run already followed by a green run of the same workflow | Note as self-resolved; no action (mirrors `SUPERSEDED-BY-GREEN` in Section A). |
| `BOT-PR-FAILING` | `app/github-actions` PR with a genuinely failed required check (not just BLOCKED) | Route to `/jmo-ci-debugger`; the soak cron will have already flipped it to `needs-review`. |

### Step 2: Build the consolidated plan

Combine the three child plans plus the Section D CI-health sweep into one report with this structure:

```text
## Maintenance Monday Plan (YYYY-MM-DD)

### Backlog snapshot
- Manual issues open: N
- Dependabot PRs open: M
- Open security alerts: A
- Tool-update issues open: K
- Failing crons (24-48h): F
- Stuck bot PRs (blind spot): S

### Section A: jmo-issue-triage plan (X items)
[Per-bucket summary from child skill's Step 3 + per-item actions from Step 4]
Recommend: approve / skip

### Section B: jmo-dependabot-triage plan (Y items)
[Per-bucket summary + per-item actions]
Recommend: approve / skip

### Section C: jmo-tool-update-triage plan (Z items)
[Per-bucket summary + per-item actions]
Recommend: approve / skip

### Section D: CI Health (W items)
[Per-bucket findings: STUCK-BOT-PR / FAILING-CRON / TRANSIENT-FLAKE / BOT-PR-FAILING.
For each STUCK-BOT-PR, include the exact `! gh pr merge <n> --squash --admin
--delete-branch` line the user will run. For each FAILING-CRON, link the failed
run URL and name the follow-on skill (`/jmo-ci-debugger`).]
Recommend: approve / skip

### Cross-cutting observations
[Anything noticed during consolidation, e.g., "Dependabot PR #491 closes
the same issue as bug #267 in section A — recommend merging the PR first
so section A's IMPLEMENTED-ON-MAIN close has the correct canonical reference."]
```

The "Cross-cutting observations" section is the unique value of consolidating the three plans: spotting cases where one child skill's action affects another's classification. The child skills running independently would miss these.

### Step 3: Present plan, ask for per-section approval

Display the consolidated plan and ask:

```text
Approve which sections to execute?
- Section A (jmo-issue-triage): [approve / skip]
- Section B (jmo-dependabot-triage): [approve / skip]
- Section C (jmo-tool-update-triage): [approve / skip]
- Section D (CI Health): [approve / skip]

Or: 'all' to approve all four, 'none' to abort.
```

**Stop and wait for user confirmation.** Do not proceed to Step 4 in `--dry-run` mode (default) or if no sections are approved.

### Step 4: Execute approved sections (only with explicit `--execute` flag + approved sections)

For Sections A/B/C, invoke the corresponding child skill with `--execute` in the order from Rule 2. The child skills' own Step 5 procedures handle the actual `gh` mutations.

**Section D execute is different — it has no child skill, and its highest-value action (admin-merge) is a privileged bypass the skill must not perform itself.** Execute Section D last, as follows:

- **`STUCK-BOT-PR`** → re-verify the PR is still `BLOCKED` with a green rollup (an earlier section's merge may have cleared it). If still stuck, **do not** attempt `gh pr merge --admin` from the skill — the auto-mode classifier blocks protection-bypasses for good reason, and the skill should respect that. Instead, present the exact command for the **user** to run in-session:

  ```text
  Stuck bot PR #<n> needs your admin-merge (the cron can't — personal-repo
  required-check constraint). Run this in the prompt:

  ! gh pr merge <n> --squash --admin --delete-branch
  ```

  This requires the one-time Repository-admin bypass-actor setup from Rule 6 (done 2026-05-26). If the command fails with `Required status check "quick-checks" is expected`, the bypass actor is missing — point the user to the Rule 6 setup step first. Also re-check the PR's diff before recommending the merge: an auto-update PR can carry a bump the user deliberately deferred (e.g. a pre-commit hook rev jumping a major version like mypy 1.x → 2.x, tracked in a `technical-debt` issue). If so, classify it `BOT-PR-FAILING`-adjacent: flag the deferred bump, recommend closing/regenerating rather than merging.

- **`FAILING-CRON`** / **`BOT-PR-FAILING`** → do not fix workflow or script bugs inline. Report the failure with its run URL and recommend `/jmo-ci-debugger`. Routing, not repairing, keeps Section D's blast radius bounded.
- **`TRANSIENT-FLAKE`** → no action; note it as self-resolved.

If the user declines to run an admin-merge this cycle, that's fine — the PR stays flagged with `needs-review` and resurfaces next Monday. The blind spot is closed by *detection*; the merge remains a human decision.

If a child skill fails mid-execute, do not invoke subsequent children. Report:

```text
Partial failure: Section B (jmo-dependabot-triage) failed during execute.
- Completed: Section A (jmo-issue-triage) — N actions applied
- Failed:    Section B (jmo-dependabot-triage) — see error above
- Skipped:   Section C (jmo-tool-update-triage) — not attempted
- Skipped:   Section D (CI Health) — not attempted (runs last)

Recommend: investigate Section B failure manually, then re-run
`/maintenance-monday --execute` once resolved (Section A will be a no-op
because its actions are already applied).
```

### Step 5: Verification

After all approved children complete, re-run the Live Context queries to confirm the backlog counts dropped as expected. If a count is unchanged when an approved section claimed to act on items, flag it for investigation — likely a silent `gh` failure inside the child skill.

For **Section D**, verification is two-part:

1. **Stuck PR drained?** If the user ran an admin-merge, confirm the PR is `MERGED` (`gh pr view <n> --json state`). If a `FAILING-CRON` was routed to `/jmo-ci-debugger`, note it as handed off (not resolved this cycle).
2. **Cron self-healing?** Optionally trigger the maintenance cron to confirm it now goes green even with a stuck PR present: `gh workflow run maintenance.yml`, then check the next "Repository Maintenance" run's conclusion. A green run with a stuck PR still open is the *correct* steady state under the fail-soft design (the PR is flipped to `needs-review`, not merged).

## Failure Modes

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| Child skill not found when orchestrator tries to invoke it | Skill renamed, deleted, or path changed | Verify `.claude/skills/<child>/SKILL.md` exists; check `INDEX.md` for current slash command name |
| Consolidated plan is empty for one section | Child skill returned an empty plan (backlog truly empty for that scope) | Normal — report "Section X: no items" in the consolidated view |
| Consolidated plan has duplicated items across sections | An issue is referenced by both `jmo-issue-triage` (as a bug) and `jmo-dependabot-triage` (as PR closing reference) | Note in "Cross-cutting observations" but don't dedupe — each child skill operates in its own scope |
| Per-section approval not respected (skipped section's items get executed) | Orchestrator misread the user's approval response | Always parse the approval into an explicit `{A: bool, B: bool, C: bool, D: bool}` map before Step 4; re-confirm with the user if parse is ambiguous |
| Section D shows a stuck bot PR every week and it never drains | The cron *cannot* auto-merge `GITHUB_TOKEN`-authored PRs on a personal repo (required-check + bypass constraints); it flips them to `needs-review` | Expected by design — the user admin-merges via the surfaced `! gh pr merge <n> --squash --admin --delete-branch`. This is the blind spot working as intended, not a bug |
| The skill tries to `gh pr merge --admin` itself and is denied | Section D execute attempted a protection-bypass instead of handing it to the user | Correct behavior is to *surface* the `!` command; never auto-run admin-merge. See Step 4 Section D |
| Approval response includes per-item skip ("skip section A item 3") | User wants fine-grained control this skill doesn't support | Tell the user: "this skill approves per-section batches only; for per-item control, run `/jmo-issue-triage --dry-run` then `--execute` directly with manual selection" |
| Total runtime exceeds 5 minutes during discovery | Three children running sequentially, each with `gh` queries | Acceptable for weekly cadence; if too slow, run children directly with their cached `gh` results |

## Examples

### Routine Monday-morning sweep

```text
/maintenance-monday
```

Defaults to dry-run. Discovers all three triage scopes plus the Section D CI-health sweep, presents the consolidated plan, waits for per-section approval. Read the plan, decide which sections to execute.

### Execute after reviewing

```text
/maintenance-monday --execute
```

Re-runs discovery (in case GitHub state changed since the dry run), shows plan one more time, asks per-section approval, executes approved sections in stable order.

### Pre-release backlog clearance

```text
/maintenance-monday
```

Run before tagging `v1.0.6`. Approve sections that align with the release scope; skip sections that introduce risk during the release freeze window.

## Project Policy Encoded

- **Per-section approval, not per-item** — for v1, granularity is at the child-skill batch level. Documented as a Rule 3 limitation; expand later only if it earns its complexity.
- **Stable child-skill order** — issue triage → Dependabot triage → tool-update triage. Don't reorder; the ordering encodes blast-radius assumptions.
- **No atomicity across children** — partial execute failures leave prior children's changes in place. Matches the failure model of running the three skills sequentially today.
- **Skip discovery on empty backlog** — Rule 5; respect the user's time. If nothing is pending, say so and exit. Exception: a non-zero Section D count (red cron or stuck PR) always warrants proceeding.
- **CI health is never out of scope** — Section D (Rule 6) makes "fix CI fully" a standing obligation of the Monday sweep, not an afterthought. The skill *detects and surfaces* CI rot (failing crons, stuck `app/github-actions` PRs) and *routes* repairs (`/jmo-ci-debugger`) or *hands the user* the one-line admin-merge. It does **not** autonomously rewrite workflow/script code or perform protection-bypass merges itself — detection closes the blind spot; the privileged action stays a human decision.
- **Local execution only** — this skill runs in the user's Claude Code session. No background Routines, no GitHub Actions, no API key requirement. Inherits the [`solo-dev-longevity-bias`](../../../memory/feedback_solo-dev-longevity-bias.md) policy from the child skills.
- **`disable-model-invocation: true`** — only invoke on explicit `/maintenance-monday` slash command. Never auto-fire because Claude thinks the user's question is about maintenance. The blast radius of a wrongly-fired triage-of-everything is too large for auto-invocation.

## See Also

- `.claude/skills/jmo-issue-triage/SKILL.md` — child skill for manual issues (Section A)
- `.claude/skills/jmo-dependabot-triage/SKILL.md` — child skill for Dependabot PRs + alerts (Section B)
- `.claude/skills/jmo-tool-update-triage/SKILL.md` — child skill for `app/github-actions` tool-version issues (Section C)
- `.claude/skills/merge-pr/SKILL.md` — used downstream when an approved Dependabot section requires a custom merge
- `.claude/skills/jmo-ci-debugger/SKILL.md` — follow-on for Section D `FAILING-CRON` / `BOT-PR-FAILING` findings (the skill routes here rather than fixing CI inline)
- `scripts/dev/auto_merge_tool_bumps.py` — the soak-window cron; its fail-soft `flip_blocked_pr` is what keeps `maintenance.yml` green while Section D surfaces the stuck PR for admin-merge
- [`reference_clawsweeper-issue-triage-patterns.md`](../../../memory/reference_clawsweeper-issue-triage-patterns.md) — upstream reference for the patterns inherited by Section A
- [`feedback_solo-dev-longevity-bias.md`](../../../memory/feedback_solo-dev-longevity-bias.md) — policy on avoiding background automation that motivated this skill's local-only design
