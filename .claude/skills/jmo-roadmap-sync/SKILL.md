---
name: jmo-roadmap-sync
description: >
  Keeps ROADMAP.md, phase-* labels, and the GitHub Project board in alignment
  after releases and quarterly reviews. Classifies drift into three buckets
  (ROADMAP-DRIFT, PHASE-ASSIGNMENT-DRIFT, PROJECT-BOARD-DRIFT), presents a
  plan, and executes label and board adjustments under user approval. Read-only
  by default; ROADMAP.md edits require explicit user confirmation. Does NOT
  close issues (that is jmo-issue-triage's job) and does NOT modify CHANGELOG.md.
argument-hint: "[--dry-run | --execute] (default: dry-run, plan mode only)"
user-invocable: true
context: fork
allowed-tools: Bash, Read, Grep, Edit, Write
---

## Live Context

**Open issues carrying the `roadmap` label (title + number + labels + state):**
!gh issue list --repo jimmy058910/jmo-security-repo --label roadmap --state open --json number,title,labels,createdAt --limit 50 2>/dev/null

**Open issues per phase label:**
!gh issue list --repo jimmy058910/jmo-security-repo --label phase-a --state open --json number,title,labels --limit 30 2>/dev/null
!gh issue list --repo jimmy058910/jmo-security-repo --label phase-b --state open --json number,title,labels --limit 30 2>/dev/null
!gh issue list --repo jimmy058910/jmo-security-repo --label phase-c --state open --json number,title,labels --limit 30 2>/dev/null
!gh issue list --repo jimmy058910/jmo-security-repo --label phase-d --state open --json number,title,labels --limit 30 2>/dev/null
!gh issue list --repo jimmy058910/jmo-security-repo --label phase-e --state open --json number,title,labels --limit 30 2>/dev/null

**ROADMAP.md current contents:**
!cat ROADMAP.md 2>/dev/null

**GitHub Project board list (owner-scoped):**
!gh project list --owner jimmy058910 2>/dev/null

**Project board items (replace `<NUM>` with project number from list above):**
!gh project item-list `<NUM>` --owner jimmy058910 --format json 2>/dev/null

**Current branch (must be main or a fresh sync branch):**
!git -C "$PWD" rev-parse --abbrev-ref HEAD

---

## Purpose

Maintain a single consistent view of roadmap state across three surfaces:

1. **ROADMAP.md** — canonical source-of-truth; sections map to phases A–E
2. **Phase labels** (`phase-a` through `phase-e`) — applied to GitHub issues
3. **GitHub Project board** — cards for open roadmap issues, columns by status

After each release or quarterly review, these surfaces drift apart. A ROADMAP.md
item gets marked complete but the tracking issue stays open with its old labels;
an issue is created for a new roadmap item but the Project board card is never
added; a phase gets re-scoped and labels fall out of step. This skill finds and
fixes all three classes of drift in one pass.

## When to Use

- **Post-release** — after a `v*` tag is pushed and the release branch lands on
  main; use the cron trigger or invoke manually once CI goes green.
- **After editing ROADMAP.md** — to propagate phase re-scoping to labels and
  the board.
- **Quarterly review** — full pass over all roadmap issues regardless of recent
  releases.
- **When a phase-* label assignment changes** — to catch downstream board drift.

## When NOT to Use

- **During an in-flight release** — ROADMAP.md may be mid-edit; wait for the
  release PR to merge before syncing.
- **When the working tree is dirty** — the skill may need to write ROADMAP.md
  (with user confirmation); a clean commit base is required.
- **To close issues** — use `/jmo-issue-triage` for closures; this skill only
  re-labels and adjusts board cards.
- **To update CHANGELOG.md** — that belongs to `release.yml` automation.

## Sync Rules

### Bucket 1: ROADMAP-DRIFT

A drift exists when either of these is true:

- An open issue carries the `roadmap` label, but the matching ROADMAP.md item
  is marked as **complete** (checkbox `[x]`, struck-through text, or under a
  "Completed" section header).
- A ROADMAP.md item is still listed as **in-progress or planned** but has no
  open issue with the `roadmap` label (the tracking issue was accidentally closed
  or never created).

Actions allowed (no user confirmation needed unless noted):

| Case | Action |
|------|--------|
| Issue open, ROADMAP item complete | Add comment on issue noting the ROADMAP completion; flag for user to decide close vs keep-open |
| ROADMAP item active, no tracking issue | Recommend `gh issue create` with the roadmap item title + `roadmap` label; show draft, wait for approval before creating |
| ROADMAP item marked complete but text is ambiguous | Flag as needs-review; do NOT edit ROADMAP.md without explicit user confirmation |

### Bucket 2: PHASE-ASSIGNMENT-DRIFT

ROADMAP.md organizes items under Phase sections (A–E). An issue has drift when:

- Its title references "Phase X" but it carries a `phase-y` label (y ≠ x).
- It has the `roadmap` label but no `phase-*` label at all.
- A phase label is assigned but the corresponding phase section in ROADMAP.md
  no longer lists that item (phase was re-scoped upstream).

Phase label → ROADMAP.md section mapping:

| Label | ROADMAP.md Section | Theme |
|-------|--------------------|-------|
| `phase-a` | Phase A | Foundation & Distribution |
| `phase-b` | Phase B | CI/CD Integration |
| `phase-c` | Phase C | Extensibility & Flexibility |
| `phase-d` | Phase D | Enterprise & Revenue |
| `phase-e` | Phase E | Advanced UI |

Actions:

- **Wrong label**: `gh issue edit <n> --remove-label phase-X --add-label phase-Y`
- **Missing label**: `gh issue edit <n> --add-label phase-Z` (infer Z from ROADMAP.md section)
- **Phase re-scoped**: flag for user; do not silently re-assign

### Bucket 3: PROJECT-BOARD-DRIFT

A drift exists when:

- An open issue with the `roadmap` label has no card on the Project board.
- A Project board card exists for an issue that is now closed.
- A card's status column doesn't match the issue state (e.g. issue is In Progress
  but card is in Backlog).

Actions:

```bash
# Add missing card
gh project item-add <board-N> --owner jimmy058910 --url https://github.com/jimmy058910/jmo-security-repo/issues/<issue-n>

# Archive stale card (closed issue)
gh project item-archive <board-N> --owner jimmy058910 --id <card-id>

# Update card status field (column)
gh project item-edit --project-id <board-N> --id <card-id> --field-id <status-field-id> --single-select-option-id <option-id>
```

Note: `gh project` commands require the `project` OAuth scope. If commands
return 403 or "insufficient scopes", run:

```bash
gh auth refresh -s project
```

## Order of Operations

1. **Read all sources in parallel** — fetch ROADMAP.md, all `roadmap`-labeled
   issues, all `phase-*` labeled issues, and Project board state simultaneously.
2. **Build the drift table** — one row per issue/ROADMAP item, flagged by bucket.
3. **Present the plan** — show the full table grouped by bucket; stop and wait
   for user approval.
4. **Execute under approval** — apply label changes first (cheap, reversible),
   then board edits, then any ROADMAP.md edits (most invasive, user must confirm
   each one explicitly).
5. **Verify** — re-run the Live Context queries and confirm drift count reaches 0.

## Workflow Steps

### Step 1: Discovery (read-only, automatic)

The Live Context block executes at invocation. Verify data returned for all
five `phase-*` label queries and the project board list. If `gh` is
unauthenticated, abort:

```bash
gh auth status || { echo "ERROR: gh not authenticated; run gh auth login"; exit 1; }
```

If project board list returns empty, the board may not yet be created:

```bash
gh project list --owner jimmy058910
# If empty: "No project board found — skipping Bucket 3 checks."
```

### Step 2: Build the drift table

```text
| Issue # | Title                        | ROADMAP status | Labels (phase) | Correct phase | Board card? | Drift bucket(s)        |
|---------|------------------------------|----------------|----------------|---------------|-------------|------------------------|
| #38     | ROADMAP #10: Web UI          | planned        | phase-e        | phase-e       | missing     | PROJECT-BOARD-DRIFT    |
| #37     | GitHub App integration       | planned        | (none)         | phase-b       | missing     | PHASE-ASSIGNMENT-DRIFT |
| #34     | Plugin System                | planned        | phase-c        | phase-c       | present     | (clean)                |
| #42     | ROADMAP: SAML SSO            | complete [x]   | phase-d        | phase-d       | present     | ROADMAP-DRIFT          |
```

### Step 3: Present the plan (REQUIRED — do not skip)

```text
## Roadmap Sync Plan (N issues reviewed)

### Bucket 1 — ROADMAP-DRIFT (X items)
- #42 SAML SSO: ROADMAP marks complete but issue is open. Flag for closure? (needs user decision)

### Bucket 2 — PHASE-ASSIGNMENT-DRIFT (X items)
- #37 GitHub App: no phase label; ROADMAP places it in Phase B → will add `phase-b`

### Bucket 3 — PROJECT-BOARD-DRIFT (X items)
- #38 Web UI: open roadmap issue missing from board → will add card
- #55 (closed): board card still active → will archive

Approve to execute, or list specific items to skip.
```

**Stop and wait for user confirmation.** Do not proceed to Step 4 in `--dry-run`
mode (default).

### Step 4: Execute (only with explicit `--execute` flag or user approval)

```bash
# Fix phase label drift
gh issue edit 37 --repo jimmy058910/jmo-security-repo --add-label phase-b

# Add missing board card
gh project item-add <N> --owner jimmy058910 \
  --url https://github.com/jimmy058910/jmo-security-repo/issues/38

# Archive card for closed issue
gh project item-archive <N> --owner jimmy058910 --id <card-id>
```

ROADMAP.md edits (e.g. marking an item complete, re-phasing an item) are shown
as a diff and require explicit per-edit user confirmation before any `Edit` call.

### Step 5: Verification

Re-run the Live Context queries. Expected end state:

- All `roadmap`-labeled open issues have a `phase-*` label matching ROADMAP.md.
- No open `roadmap` issue is missing a Project board card.
- No board card exists for a closed issue.
- ROADMAP.md completion markers match open/closed issue states.

## Failure Modes

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| `gh project` returns 403 | Token lacks `project` scope | `gh auth refresh -s project` |
| `gh project list` returns empty | Board not yet created | Skip Bucket 3; note "board pending creation" in plan |
| Project board ID changes between runs | Board was recreated | Re-run discovery; update `<N>` in commands |
| ROADMAP.md has no phase headers | Format changed or file is stub | Abort; flag to user — cannot classify without headers |
| `phase-*` label doesn't exist in repo | Label was deleted or never created | `gh label create phase-X --color <hex> --description "..."` before applying |
| Issue title says "Phase A" but ROADMAP places it in Phase C | Title was written when scope was different | Flag as PHASE-ASSIGNMENT-DRIFT; recommend title update alongside label change |
| Board card field IDs differ from expected | Project schema changed | Re-fetch field IDs: `gh project field-list <N> --owner jimmy058910 --format json` |

## Examples

### Post-release sync

After `v1.0.6` ships:

```text
/jmo-roadmap-sync
```

Defaults to dry-run. Discovery runs, drift table is built, plan is presented.
Typical post-release result: 1–3 PROJECT-BOARD-DRIFT items (new issues created
during the release cycle not yet on the board) and 0–1 ROADMAP-DRIFT items
(items completed in the release but ROADMAP.md not yet updated).

### Quarterly review

```text
/jmo-roadmap-sync --execute
```

Full pass. Expects more PHASE-ASSIGNMENT-DRIFT items as the roadmap evolves.
The skill will show a diff for any ROADMAP.md edit and require confirmation
before writing. Typical quarterly result: 3–7 items across all three buckets.

### Targeted phase re-label

After manually moving items between phases in ROADMAP.md:

```text
/jmo-roadmap-sync
```

Bucket 2 will surface all issues whose labels no longer match their ROADMAP.md
section. Approve the relabeling; board cards are then auto-moved if status
columns map to phase labels.

## Project Policy Encoded

- **ROADMAP.md is the source-of-truth** — label assignments and board column
  placements follow ROADMAP.md, not the other way around. When they conflict,
  ROADMAP.md wins unless the user overrides.
- **Phase labels follow CHANGELOG sections** — new phases are added to
  CHANGELOG.md `## Unreleased` before the corresponding `phase-*` label is
  created, so both surfaces stay in sync.
- **Solo-dev longevity bias** — no automated cron re-labeling; this skill runs
  on explicit invocation or post-release hook, not on every issue event. Minimal
  infrastructure overhead (no webhooks, no GitHub Actions label-bot).
- **Issue closure is out of scope** — ROADMAP-DRIFT bucket flags issues for
  potential closure but never executes `gh issue close`. Closures go through
  `/jmo-issue-triage` where full triage context is available.
- **Long-lived roadmap issues are intentional** — issues like #38 (Web UI), #37
  (GitHub App), #34 (Plugin System) are intentionally open and 188+ days old.
  Age alone is not a drift signal; only ROADMAP.md completion status is.

## See Also

- `.claude/skills/jmo-issue-triage/SKILL.md` — handles issue closures that
  ROADMAP-DRIFT flags; invoke after this skill if closures are warranted
- `.claude/skills/jmo-dependabot-triage/SKILL.md` — sibling maintenance skill;
  run both in the same post-release session
- `.claude/skills/content-generator/SKILL.md` — CHANGELOG → blog post pipeline;
  run after roadmap sync when a phase milestone is reached
- `ROADMAP.md` — canonical roadmap document at repo root
- `CHANGELOG.md` — phase-section headers kept in sync with ROADMAP.md phases
