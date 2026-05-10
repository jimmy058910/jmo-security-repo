---
name: jmo-tool-update-triage
description: >
  Triage of all open tool-version update issues created by the weekly
  `check-versions` cron (app/github-actions, label: dependencies).
  Classifies each issue into one of five buckets — BATCH-MINOR,
  MAJOR-BUMP-READABLE, MAJOR-BUMP-MIGRATION, MANUAL-TOOL,
  PLACEHOLDER-CURRENT — and produces a plan-mode review with explicit
  per-item recommendations. Designed for weekly cadence, run after the
  Sunday auto-update-tools job to separate what cron will handle from what
  needs hands-on work. JMo Security policy: NEVER edit Dockerfiles
  directly, always `--sync` after every version bump, conservative bumps
  preferred.
argument-hint: "[--dry-run | --execute] (default: dry-run, plan mode only)"
user-invocable: true
context: fork
allowed-tools: Bash, Read, Grep, Edit, Write
---

## Live Context

**Open tool-version update issues (app/github-actions, label: dependencies):**
!gh issue list --repo jimmy058910/jmo-security-repo --author "app/github-actions" --label dependencies --state open --json number,title,body,createdAt --limit 100 2>/dev/null

**Current versions.yaml snapshot (tool → version cross-reference):**
!grep -E '^\s{2}[a-z_-]+:|^\s{4}version:' /c/Projects/jmo-security-repo/versions.yaml 2>/dev/null | head -80

**MANUAL_INSTALL_TOOLS (tools exempt from Docker image bumps):**
!grep -A 1 "MANUAL_INSTALL_TOOLS" /c/Projects/jmo-security-repo/scripts/core/tool_registry.py | head -4

**Last 5 maintenance.yml runs (check whether auto-update-tools swept recently):**
!gh run list --repo jimmy058910/jmo-security-repo --workflow=maintenance.yml --limit 5 --json conclusion,createdAt,event,name 2>/dev/null

**Current branch (must be `main` or a fresh triage branch):**
!git -C "$PWD" rev-parse --abbrev-ref HEAD

---

## Purpose

Weekly sweep of the tool-version update issue backlog created by `update_versions.py --check-outdated --create-issues` (runs every Sunday 02:00 UTC via `maintenance.yml` → `check-versions` job). Produces a structured plan classifying every open issue into one of five buckets:

1. **BATCH-MINOR** — patch or minor bump; auto-update-tools will apply it within 7 days
2. **MAJOR-BUMP-READABLE** — single-major bump, stable CLI surface, low blast radius
3. **MAJOR-BUMP-MIGRATION** — single-major bump requiring adapter/parser changes
4. **MANUAL-TOOL** — tool is in `MANUAL_INSTALL_TOOLS`; `versions.yaml` is cosmetic only
5. **PLACEHOLDER-CURRENT** — `versions.yaml` has `0.0.0` or missing entry (non-manual tools only)

The skill **never executes destructive actions without user approval**. It enters plan mode by default.

## When to Use

- Weekly, Monday AM — after the Sunday `auto-update-tools` sweep creates fresh PRs and the `check-versions` job opens new issues.
- Before any release (`v*` tag) — clear the MAJOR-BUMP-READABLE backlog so the tag ships with current tooling.
- When the issue count > 10 and you want to separate cron-handled work from manual decisions.
- When a tool's major release lands and you need to evaluate adapter impact before bumping.

## When NOT to Use

- During an in-flight release (version bumps mid-release break the release checklist).
- When working tree is dirty on `main` — `MAJOR-BUMP-READABLE` execution needs a clean commit base.
- For Dependabot PRs (use `/jmo-dependabot-triage` instead).
- For general bug/enhancement issues (use `/jmo-issue-triage` instead).

## Triage Rules

### Rule 1: MANUAL-TOOL classification takes priority

**Evaluate this bucket first**, before any other classification. If the tool name in the issue title appears in `MANUAL_INSTALL_TOOLS` (`falco`, `afl++`/`afl-fuzz`, `mobsf`, `akto`), classify as MANUAL-TOOL regardless of what `versions.yaml` shows. These 4 tools are in `PROFILE_TOOLS["deep"]` but intentionally absent from all Docker images. Bumping `versions.yaml` is cosmetic tracking only.

Note: "Update falco to v0.43.1" with current `0.0.0` looks like PLACEHOLDER-CURRENT, but falco is manual — route it here, not to bucket 5.

### Rule 2: PLACEHOLDER-CURRENT (non-manual tools only)

A non-manual tool with `version: 0.0.0` or no entry in `versions.yaml` indicates either a stub registry entry that was never wired to a real install path, or a tool added speculatively. Do NOT assume it will auto-resolve. File a `tech-debt` issue to investigate the install path; close the auto-issue with a link.

### Rule 3: BATCH-MINOR — patch and minor bumps

Parse the issue body for `Current version: X.Y.Z` and `Latest version: A.B.C`. If `A == X` (same major) this is a patch or minor bump. The `auto-update-tools` cron job (Sunday 00:00 UTC, `--level=minor`) will apply it within 7 days. **The issue does NOT auto-close when the upgrade lands** — `_close_superseded_version_issues()` only fires when upstream releases a further bump (creating a new issue, closing the old). After the cron PR merges, close the issue manually with a link to the PR, or leave it to supersede naturally on the next upstream release.

Action: no manual work needed. Confirm cron is not broken (check Live Context: last maintenance.yml run).

### Rule 4: MAJOR-BUMP-READABLE — single-major bump, stable surface

`A > X` by exactly one major, and the tool has a stable CLI/flag surface with no known parser-breaking changes between those majors. Examples: `trivy 0.x → 1.0`, `semgrep 1.x → 2.0` with same SARIF output schema.

Execute via `update_versions.py`:

```bash
python3 scripts/dev/update_versions.py --tool <toolname> --version <A.B.C>
python3 scripts/dev/update_versions.py --sync
pytest tests/test_tool_contracts.py -x -q
```

If contracts pass, open a PR with the versions.yaml + Dockerfile diffs. Use `/merge-pr`.

**NEVER edit Dockerfiles directly** — `--sync` rewrites them from `versions.yaml`.

### Rule 5: MAJOR-BUMP-MIGRATION — adapter/parser changes required

`A > X` and the tool's output schema, flag names, or SARIF structure changed between majors (e.g., a new JSON key the adapter regex relies on). The contract tests will likely catch this, but even if they pass, read the upstream changelog before declaring safe.

Action: file a `tech-debt` issue with the upstream changelog link and the adapter file to update. Close the auto-issue with the tech-debt link. Do NOT bump until adapter is updated.

### Rule 6: Version bump magnitude table

| Bump | Example | Bucket |
|------|---------|--------|
| Patch | `1.2.3 → 1.2.4` | BATCH-MINOR |
| Minor | `1.2.3 → 1.5.0` | BATCH-MINOR |
| Single major, stable surface | `1.x → 2.0` | MAJOR-BUMP-READABLE |
| Single major, schema change | `trivy 0.x → 1.0` + new JSON keys | MAJOR-BUMP-MIGRATION |
| Multi-major leap | `0.x → 3.0` | MAJOR-BUMP-MIGRATION (treat conservatively) |
| Any major, tool in MANUAL_INSTALL_TOOLS | any | MANUAL-TOOL |
| Any, `versions.yaml` is `0.0.0`, non-manual | any | PLACEHOLDER-CURRENT |

## Order of Operations

When executing the plan, always follow this order:

1. **Confirm BATCH-MINOR set will land via cron** — check the last maintenance.yml run status in Live Context. If `auto-update-tools` conclusion is `failure`, the cron is broken; escalate to `/jmo-ci-debugger` before declaring these "will resolve."
2. **Handle MAJOR-BUMP-READABLE as a single PR** — batch all readable majors into one commit (`--tool A --version X && --tool B --version Y && --sync`), run contracts, ship via `/merge-pr`. One PR keeps the diff reviewable.
3. **File tech-debt issues for MIGRATION before closing auto-issues** — never close without a tracked issue. The auto-issue thread is the only record of the upstream bump; losing it loses the signal.
4. **Close MANUAL-TOOL issues** — comment explains the status so the pattern is documented for future maintainers.
5. **Investigate PLACEHOLDER-CURRENT** — read `scripts/core/install_config.py` and the relevant adapter to determine whether the tool has a real install path. If yes, wire it; if no, the stub is dead code — note it in the tech-debt issue.

## Workflow Steps

### Step 1: Discovery (read-only, automatic)

Live Context executes at invocation. Verify data was returned. If `gh` is unauthenticated, abort:

```bash
gh auth status || { echo "ERROR: gh not authenticated; run gh auth login"; exit 1; }
```

### Step 2: Build the classification table

For each open issue, extract tool name + current/latest versions from body, then route:

```text
| Issue # | Tool       | Current | Latest | Bucket                | Action                          |
|---------|------------|---------|--------|-----------------------|---------------------------------|
| #441    | falco      | 0.0.0   | 0.43.1 | MANUAL-TOOL           | Close with comment              |
| #438    | trivy      | 0.58.1  | 0.59.0 | BATCH-MINOR           | Cron will apply; no action      |
| #435    | semgrep    | 1.155.0 | 2.0.0  | MAJOR-BUMP-READABLE   | --tool bump + --sync + PR       |
| #432    | bandit     | 1.8.5   | 2.0.0  | MAJOR-BUMP-MIGRATION  | File tech-debt, close auto-issue|
| #429    | nuclei     | 0.0.0   | 3.3.4  | PLACEHOLDER-CURRENT   | Investigate install path        |
```

### Step 3: Present the plan (REQUIRED — do not skip)

```text
## Tool Update Triage Plan (N issues)

### Will resolve via cron — BATCH-MINOR (X issues)
- #438 trivy 0.58.1 → 0.59.0 — auto-update-tools will apply within 7 days
  (Last cron run: SUCCESS 2026-05-04)

### Will bump manually — MAJOR-BUMP-READABLE (X issues)
- #435 semgrep 1.155.0 → 2.0.0 — stable SARIF output, contract tests expected to pass

### Will file tech-debt — MAJOR-BUMP-MIGRATION (X issues)
- #432 bandit 1.8.5 → 2.0.0 — new JSON schema for issue.extra fields (scripts/core/adapters/bandit_adapter.py)

### Will close as MANUAL-TOOL (X issues)
- #441 falco 0.0.0 → 0.43.1 — manual install tool, versions.yaml tracking only

### Will investigate — PLACEHOLDER-CURRENT (X issues)
- #429 nuclei 0.0.0 → 3.3.4 — non-manual tool with 0.0.0 stub

Approve to execute, or list specific items to skip.
```

**Stop and wait for user confirmation.** Do not proceed in `--dry-run` mode (default).

### Step 4: Execute (only with explicit `--execute` flag)

```bash
# 4a: Batch all MAJOR-BUMP-READABLE bumps (never edit Dockerfiles directly)
python3 scripts/dev/update_versions.py --tool semgrep --version 2.0.0
python3 scripts/dev/update_versions.py --sync
pytest tests/test_tool_contracts.py -x -q
# If contracts pass, commit and open PR
git checkout -b tool-bump/major-readable-$(date +%Y%m%d)
git add versions.yaml Dockerfile.deep Dockerfile.balanced Dockerfile.slim Dockerfile.fast
git commit -m "chore: bump major-readable tools (semgrep 2.0.0, ...)"
# Then: /merge-pr

# 4b: File tech-debt issue for each MAJOR-BUMP-MIGRATION
gh issue create --repo jimmy058910/jmo-security-repo \
  --title "tech-debt: bump bandit 1.x → 2.0.0 (schema migration)" \
  --label tech-debt,dependencies \
  --body "$(cat <<EOF
Tool update issue #432 flagged bandit 2.0.0 available.
Requires adapter migration: scripts/core/adapters/bandit_adapter.py
Upstream changelog: https://github.com/PyCQA/bandit/blob/main/CHANGELOG
- [ ] Review output schema changes between 1.x and 2.0.0
- [ ] Update parser regex / JSON key references in adapter
- [ ] Add/update adapter contract tests
- [ ] Run: update_versions.py --tool bandit --version 2.0.0 && --sync
EOF
)"
gh issue close 432 --repo jimmy058910/jmo-security-repo \
  --comment "Migration required — tracked in #<new-issue>. Closing auto-issue."

# 4c: Close MANUAL-TOOL issues
gh issue close 441 --repo jimmy058910/jmo-security-repo \
  --comment "falco is in MANUAL_INSTALL_TOOLS — not present in Docker images. versions.yaml entry tracks the version for reference only. No Dockerfile change will occur on bump. See scripts/core/tool_registry.py:157."

# 4d: PLACEHOLDER-CURRENT — read adapter and install_config before deciding
grep -n "nuclei" scripts/core/install_config.py
grep -n "nuclei" scripts/core/adapters/nuclei_adapter.py 2>/dev/null
# If real install path found: wire it, bump, and close issue resolved
# If stub only: file tech-debt issue, close auto-issue with link
```

### Step 5: Verification

After execution, re-run Live Context queries and confirm:

- MAJOR-BUMP-READABLE PR is open (or merged if `/merge-pr` ran)
- Tech-debt issues exist for all MIGRATION items with the right labels
- MANUAL-TOOL and PLACEHOLDER-CURRENT auto-issues are closed with explanatory comments
- BATCH-MINOR issues remain open (normal — they close when cron applies the bump or upstream supersedes)

## Failure Modes

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| `gh auth status` fails | Token expired or wrong scope | `gh auth refresh -s repo` |
| `auto-update-tools` last run shows `failure` | Cron broken; BATCH-MINOR issues won't sweep | Invoke `/jmo-ci-debugger` against maintenance.yml before declaring batch-minor safe |
| `update_versions.py --tool X --version Y` exits non-zero | Tool name not in `versions.yaml` schema, or version string format wrong | Check `versions.yaml` key naming; may need to add a new entry block first |
| `--sync` runs but Dockerfiles unchanged | Tool is not referenced in any Dockerfile (e.g., Python-only tool in `python_tools` block) | Expected for pip-only tools; Dockerfile only updates binary/apt sections |
| Contract tests fail post-bump | Major version changed output schema (e.g., new SARIF key, removed field) | Reclassify issue from MAJOR-BUMP-READABLE → MAJOR-BUMP-MIGRATION; revert bump, file tech-debt |
| Issue reopens next Sunday | Upstream bumped again before cron applied the previous bump | New issue supersedes the old one via `_close_superseded_version_issues()`; triage the new issue normally |
| BATCH-MINOR issue still open 2 weeks after cron ran | Cron applied the bump (PR merged) but issue wasn't manually closed | Close with link to the merged PR; issue won't auto-close until upstream bumps again |

## Examples

### Routine weekly sweep

```text
/jmo-tool-update-triage
```

Defaults to dry-run. Reviews all open `app/github-actions` + `dependencies` issues, presents plan, waits for approval.

### Execute a previously-reviewed plan

```text
/jmo-tool-update-triage --execute
```

Re-runs discovery (state may have changed), shows plan one more time, executes on confirmation.

### Sample plan output — real backlog with 6 issues

```text
## Tool Update Triage Plan (6 issues)

### Will resolve via cron — BATCH-MINOR (3 issues)
- #451 checkov 3.2.499 → 3.2.501 — patch, cron will apply
- #449 trivy 0.58.2 → 0.59.0 — minor, cron will apply
- #447 ruff 0.15.1 → 0.15.2 — patch, cron will apply
  Last cron run: SUCCESS 2026-05-04 (auto-update-tools)

### Will bump manually — MAJOR-BUMP-READABLE (1 issue)
- #445 semgrep 1.155.0 → 2.0.0 — SARIF output schema stable per changelog

### Will close as MANUAL-TOOL (1 issue)
- #441 falco 0.0.0 → 0.43.1 — manual install, not in Docker images

### Will investigate — PLACEHOLDER-CURRENT (1 issue)
- #439 nuclei 0.0.0 → 3.3.4 — non-manual tool, stub entry in versions.yaml

Approve to execute, or list specific items to skip.
```

### Batch upgrade walkthrough (MAJOR-BUMP-READABLE)

```bash
# 1. Bump each tool individually (never batch into one --tool call)
python3 scripts/dev/update_versions.py --tool semgrep --version 2.0.0

# 2. Sync all Dockerfiles from versions.yaml
python3 scripts/dev/update_versions.py --sync

# 3. Verify no Dockerfile was manually edited
git diff Dockerfile.* | grep '^+' | grep -v versions  # should be empty or version strings only

# 4. Run contract tests to catch output schema breakage
pytest tests/test_tool_contracts.py -x -q

# 5. Ship via /merge-pr (squash to main, dev syncs automatically)
```

## Project Policy Encoded

- **NEVER manually edit Dockerfiles** — `versions.yaml` is the source-of-truth for all tool versions. Always use `update_versions.py --tool X --version Y` then `--sync`. See CLAUDE.md "CRITICAL" and [docs/VERSION_MANAGEMENT.md](../../docs/VERSION_MANAGEMENT.md).
- **Always run `--sync` after every `--tool` bump** — Dockerfiles diverge from `versions.yaml` otherwise, causing image-build failures detected only at release time.
- **Run contract tests before opening the PR** — `pytest tests/test_tool_contracts.py` is the canary for output schema breakage. A passing contract suite is a prerequisite for MAJOR-BUMP-READABLE classification to hold.
- **Conservative bumps** — solo-dev longevity bias ([feedback memory](../../../memory/feedback_solo-dev-longevity-bias.md)): prefer batched minor over leapfrog majors. If upstream has released v2 and v3 since last sweep, do not jump to v3; assess v2 first unless v2 is itself EOL.
- **DEFER-MAJOR creates a tracked issue** — never close a migration-required auto-issue without filing the `tech-debt` issue first. The auto-issue is the only upstream-bump signal; losing it loses the trail.
- **Squash-merge to main** — via `/merge-pr`. Branch deletion is automatic. Do not push directly to `main`.

## See Also

- `.claude/skills/jmo-dependabot-triage/SKILL.md` — parallel skill for Dependabot library PRs and security alerts (separate concern from tool-version update issues)
- `.claude/skills/jmo-issue-triage/SKILL.md` — general issue triage (bugs, enhancements, tech-debt); explicitly excludes `app/github-actions` tool-version issues handled here
- `.claude/skills/jmo-roadmap-sync/SKILL.md` — roadmap and phase-label alignment; use after filing multiple tech-debt issues to keep board current
- `.claude/skills/merge-pr/SKILL.md` — ship the MAJOR-BUMP-READABLE PR after contract tests pass
- [docs/VERSION_MANAGEMENT.md](../../docs/VERSION_MANAGEMENT.md) — canonical reference for `update_versions.py` flags, `versions.yaml` schema, and the update-check mechanism
