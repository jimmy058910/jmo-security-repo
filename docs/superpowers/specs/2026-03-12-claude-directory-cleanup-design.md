# .claude/ Directory Cleanup & Consolidation

**Date:** 2026-03-12
**Scope:** All files in `.claude/` EXCEPT `agents/`, `skills/`, `mcp.json`, `settings.local.json`
**Approach:** Full consolidation (Approach B) with cherry-pick archiving
**Risk:** Low (all target files are gitignored, no public-facing impact)

---

## Context

The `.claude/` directory accumulated ~228 KB of markdown + ~63 MB of stale worktree caches over 5 months of development. Most files are completed session artifacts that were never cleaned up. This spec describes a tiered cleanup to reduce `.claude/` to only active, purposeful files.

### Key Constraints

- `docs/` is **public** (git-tracked) - no internal artifacts belong there
- `dev-only/` is **private** (gitignored) - safe for archives
- `.claude/` is **private** (gitignored) - only active config/guidance belongs here

---

## Changes

### Tier 1: DELETE (dead/superseded, no preservation value)

| File | Reason |
|------|--------|
| `POLICY_AS_CODE_COMPLETION_STATUS.md` | Superseded by `POLICY_CLI_IMPLEMENTATION_COMPLETE.md`; contradicts sibling |
| `POLICY_CLI_IMPLEMENTATION_COMPLETE.md` | Feature shipped Nov 2025; content lives in `docs/POLICY_AS_CODE.md` |
| `RALPH-SCAN-PROMPT.md` | Ralph infrastructure removed Feb 2026 |
| `scenario4-testing-plan.md` | Subset duplicate of `comprehensive-testing-analysis.md` |
| `AGENT_AND_SKILL_USAGE_GUIDE.md` | Stale (Oct 2025, lists 11 skills vs 14 actual); 3-way duplication with `AGENTS.md` + `INDEX.md` |
| `mcp-skills/` (entire dir, 5 files) | Zero references in codebase; `quick-coverage.py` broken; design philosophy superseded |
| `worktrees/` (entire dir, ~63 MB) | Orphaned agent session caches with 2,545 sync-conflict files; not real git worktrees |
| `plans/` (empty dir) | Unused; plans live in `dev-only/plans/` |
| `session-notes/` (empty dir) | Never used |

### Tier 2: ARCHIVE to `dev-only/archive/claude-sessions/`

| File | Reason |
|------|--------|
| `comprehensive-testing-analysis.md` | Pre-release 13-scenario testing record (completed Jan 2026); historical reference for testing approach |
| `scan-iteration-progress.md` | Completed 3/3 validation loop; documents Windows-specific perf tuning decisions |
| `TOOL_MANAGEMENT_IMPLEMENTATION_SUMMARY.md` | Likely outdated (Dec 2024); archive for architecture reference |
| `FINAL-UPDATE-GUARDRAILS-PLAN.md` | All 4 priorities implemented (pip-audit, golden tests, contracts, Windows CI); documents rationale |

### Tier 3: CONSOLIDATE

**Migrate Issue #2 from `issues-to-fix.md` into `known-issues.md`:**

- Issue #1 (Wizard --emit-script): Fixed in Feb 2026 session - do not migrate
- Issue #2 (Cross-tool dedup threshold): Still open - add to known-issues.md under new "Deduplication Effectiveness" section
- Issue #3 (Pyright imports): Low priority cosmetic - do not migrate (pyrightconfig.json can be added independently)
- Then DELETE `issues-to-fix.md`

### Tier 4: KEEP (no changes needed)

| File | Reason |
|------|--------|
| `known-issues.md` | Active tracker, updated Mar 7 (will receive Issue #2 migration) |
| `PERSONA_GUIDELINES.md` | Foundational agent persona design guide, referenced by CLAUDE.md |
| `screenshot-best-practices.md` | Practical Claude API image size guidance |
| `hooks/cleanup-session.sh` | Active hook, registered in settings.local.json |

---

## Final State

```text
.claude/
├── hooks/
│   └── cleanup-session.sh
├── known-issues.md
├── PERSONA_GUIDELINES.md
├── screenshot-best-practices.md
├── agents/                    (excluded from audit)
├── skills/                    (excluded from audit)
├── mcp.json                   (excluded from audit)
└── settings.local.json        (excluded from audit)
```

**Before:** 13 files + 5 subdirs (~228 KB + 63 MB caches)
**After:** 3 files + 1 subdir (~12 KB)

---

## CLAUDE.md Impact

All 4 references to `.claude/` remain valid:
- `.claude/known-issues.md` (line 103) - KEEPS
- `.claude/skills/INDEX.md` (line 209) - excluded from audit
- `.claude/PERSONA_GUIDELINES.md` (line 211) - KEEPS
- Generic "use `.claude/` for temporary work" (line 532) - guideline, not a file path

No CLAUDE.md updates needed.

## Migration Note

When migrating Issue #2 (dedup threshold), use the current configurable default of `0.65` (from `jmo.yml` `deduplication.similarity_threshold`), not the old hardcoded `0.75` from the original `issues-to-fix.md`.

---

## Execution Order

1. Create `dev-only/archive/claude-sessions/`
2. Move Tier 2 files to archive
3. Migrate Issue #2 into `known-issues.md`
4. Delete Tier 1 files and directories
5. Delete `issues-to-fix.md` (after migration)
6. Verify CLAUDE.md references still resolve

## Unresolved

None - all decisions confirmed with user.
