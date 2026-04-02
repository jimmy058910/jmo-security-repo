# .claude/ Directory Cleanup Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Clean up `.claude/` directory by deleting dead files, archiving historical artifacts to `dev-only/archive/claude-sessions/`, migrating open Issue #2 into `known-issues.md`, and removing empty/stale directories.

**Architecture:** Tiered file operations — create archive target first, move files, migrate content, then delete. All files are gitignored so no git history impact.

**Tech Stack:** Bash file operations, manual markdown editing

**Spec:** `docs/superpowers/specs/2026-03-12-claude-directory-cleanup-design.md`

---

## Chunk 1: Archive Setup & File Moves

### Task 1: Create Archive Directory

**Files:**
- Create: `dev-only/archive/claude-sessions/` (directory)

- [ ] **Step 1: Create the archive target directory**

```bash
mkdir -p dev-only/archive/claude-sessions
```

- [ ] **Step 2: Verify directory exists**

```bash
ls -la dev-only/archive/claude-sessions/
```
Expected: Empty directory listing

---

### Task 2: Archive Historical Files (Tier 2)

Move 4 completed-but-historically-valuable files to archive.

**Files:**
- Move: `.claude/comprehensive-testing-analysis.md` -> `dev-only/archive/claude-sessions/`
- Move: `.claude/scan-iteration-progress.md` -> `dev-only/archive/claude-sessions/`
- Move: `.claude/TOOL_MANAGEMENT_IMPLEMENTATION_SUMMARY.md` -> `dev-only/archive/claude-sessions/`
- Move: `.claude/FINAL-UPDATE-GUARDRAILS-PLAN.md` -> `dev-only/archive/claude-sessions/`

- [ ] **Step 1: Move all 4 files**

```bash
mv .claude/comprehensive-testing-analysis.md dev-only/archive/claude-sessions/
mv .claude/scan-iteration-progress.md dev-only/archive/claude-sessions/
mv .claude/TOOL_MANAGEMENT_IMPLEMENTATION_SUMMARY.md dev-only/archive/claude-sessions/
mv .claude/FINAL-UPDATE-GUARDRAILS-PLAN.md dev-only/archive/claude-sessions/
```

- [ ] **Step 2: Verify archive contents**

```bash
ls -la dev-only/archive/claude-sessions/
```
Expected: 4 files listed

- [ ] **Step 3: Verify files removed from .claude/**

```bash
ls .claude/comprehensive-testing-analysis.md 2>&1
ls .claude/scan-iteration-progress.md 2>&1
ls .claude/TOOL_MANAGEMENT_IMPLEMENTATION_SUMMARY.md 2>&1
ls .claude/FINAL-UPDATE-GUARDRAILS-PLAN.md 2>&1
```
Expected: All 4 should show "No such file or directory"

---

## Chunk 2: Content Migration

### Task 3: Migrate Issue #2 into known-issues.md

Extract the open cross-tool dedup threshold issue from `issues-to-fix.md` and add it to `known-issues.md` under a new section.

**Files:**
- Modify: `.claude/known-issues.md` (add new section before "Design Limitations")
- Delete: `.claude/issues-to-fix.md` (after migration)

- [ ] **Step 1: Add dedup effectiveness section to known-issues.md**

Insert the following before the `## Design Limitations (Won't Fix)` section in `.claude/known-issues.md`:

```markdown
## Deduplication Effectiveness

### Cross-Tool Clustering Threshold
- **Status:** Default threshold (`0.65` via `deduplication.similarity_threshold` in `jmo.yml`) produces limited cross-tool clustering on real-world scans.
- **Example:** Trivy `:latest tag used` + Hadolint `DL3006` on same Dockerfile line score ~0.39 similarity (below any reasonable threshold) because message text and rule IDs differ completely despite identical location.
- **Root Cause:** Message weight (0.40) dominates composite score; location-only matches can't overcome dissimilar messages/metadata.
- **Code:** `scripts/core/dedup_enhanced.py` (weights at line ~227), `scripts/core/normalize_and_report.py` (threshold at line ~495)
- **Options:** (a) Lower threshold further, (b) Add rule-equivalence mapping table for known cross-tool duplicates, (c) Rebalance weights toward location, (d) Make weights configurable via `jmo.yml`
- **Priority:** P2 (no data loss — findings are preserved, just not clustered)

```

- [ ] **Step 2: Update the "Last Updated" date**

Change the date line at the top of `known-issues.md`:
```text
**Last Updated:** 2026-03-12
```

- [ ] **Step 3: Verify known-issues.md has the new section**

Read `.claude/known-issues.md` and confirm the "Deduplication Effectiveness" section appears between "Dependency Conflicts" and "Design Limitations".

- [ ] **Step 4: Delete issues-to-fix.md**

```bash
rm .claude/issues-to-fix.md
```

- [ ] **Step 5: Verify deletion**

```bash
ls .claude/issues-to-fix.md 2>&1
```
Expected: "No such file or directory"

---

## Chunk 3: Delete Dead Files & Directories

### Task 4: Delete Superseded/Dead Markdown Files (Tier 1)

**Files:**
- Delete: `.claude/POLICY_AS_CODE_COMPLETION_STATUS.md`
- Delete: `.claude/POLICY_CLI_IMPLEMENTATION_COMPLETE.md`
- Delete: `.claude/RALPH-SCAN-PROMPT.md`
- Delete: `.claude/scenario4-testing-plan.md`
- Delete: `.claude/AGENT_AND_SKILL_USAGE_GUIDE.md`

- [ ] **Step 1: Delete all 5 files**

```bash
rm .claude/POLICY_AS_CODE_COMPLETION_STATUS.md
rm .claude/POLICY_CLI_IMPLEMENTATION_COMPLETE.md
rm .claude/RALPH-SCAN-PROMPT.md
rm .claude/scenario4-testing-plan.md
rm .claude/AGENT_AND_SKILL_USAGE_GUIDE.md
```

- [ ] **Step 2: Verify deletions**

```bash
ls .claude/POLICY_AS_CODE_COMPLETION_STATUS.md .claude/POLICY_CLI_IMPLEMENTATION_COMPLETE.md .claude/RALPH-SCAN-PROMPT.md .claude/scenario4-testing-plan.md .claude/AGENT_AND_SKILL_USAGE_GUIDE.md 2>&1
```
Expected: All 5 show "No such file or directory"

---

### Task 5: Delete Stale Directories

**Files:**
- Delete: `.claude/mcp-skills/` (5 files, unused utilities)
- Delete: `.claude/worktrees/` (~63 MB orphaned caches)
- Delete: `.claude/plans/` (empty directory)
- Delete: `.claude/session-notes/` (empty directory)

- [ ] **Step 1: Delete mcp-skills directory**

```bash
rm -rf .claude/mcp-skills
```

- [ ] **Step 2: Delete worktrees directory**

```bash
rm -rf .claude/worktrees
```

- [ ] **Step 3: Delete empty directories**

```bash
rmdir .claude/plans 2>/dev/null; rmdir .claude/session-notes 2>/dev/null
```

Note: Using `rmdir` (not `rm -rf`) for empty dirs as a safety check — fails if unexpectedly non-empty.

- [ ] **Step 4: Verify all 4 directories removed**

```bash
ls -d .claude/mcp-skills .claude/worktrees .claude/plans .claude/session-notes 2>&1
```
Expected: All 4 show "No such file or directory"

---

## Chunk 4: Final Verification

### Task 6: Verify Final State

- [ ] **Step 1: List remaining .claude/ contents**

```bash
ls -la .claude/
```

Expected remaining items (excluding agents/, skills/, mcp.json, settings.local.json):
- `hooks/` (directory with cleanup-session.sh)
- `known-issues.md`
- `PERSONA_GUIDELINES.md`
- `screenshot-best-practices.md`

- [ ] **Step 2: Verify CLAUDE.md references still resolve**

```bash
ls .claude/known-issues.md .claude/PERSONA_GUIDELINES.md .claude/skills/INDEX.md 2>&1
```
Expected: All 3 files exist (no errors)

- [ ] **Step 3: Verify archive contents**

```bash
ls dev-only/archive/claude-sessions/
```
Expected: 4 archived files listed

- [ ] **Step 4: Confirm cleanup complete**

Final state should be:
```text
.claude/
├── hooks/
│   └── cleanup-session.sh
├── known-issues.md
├── PERSONA_GUIDELINES.md
├── screenshot-best-practices.md
├── agents/                    (excluded)
├── skills/                    (excluded)
├── mcp.json                   (excluded)
└── settings.local.json        (excluded)
```

**Before:** 13 files + 5 subdirs (~228 KB + 63 MB caches)
**After:** 3 files + 1 subdir (~12 KB)
**Freed:** ~216 KB markdown + ~63 MB stale caches
