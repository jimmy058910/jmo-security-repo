---
name: merge-pr
description: >
  Push the current feature branch, open a PR to main, watch CI to completion,
  squash-merge when green, sync dev from main, and clean up local + remote
  branches. JMo Security project policy: PR-direct-to-main (no dev staging),
  squash-merge style, dev mirrors main post-merge. Aborts on CI failure or
  branch divergence.
argument-hint: "[PR# or PR-title-override]"
user-invocable: true
context: fork
allowed-tools: Bash, Read, Grep
---

## Live Context

**Current branch and ahead/behind state:**
!git -C "$PWD" status --short --branch 2>/dev/null | head -3

**Local branch's commits ahead of main:**
!git -C "$PWD" log --oneline main..HEAD 2>/dev/null | head -10

**dev↔main divergence (must be 0 for safe sync at end):**
!git -C "$PWD" rev-list --left-right --count origin/dev...origin/main 2>/dev/null

**Open PR for the current branch (if any):**
!gh pr view --json number,title,state,headRefName,mergeable 2>/dev/null || echo "no PR yet for this branch"

---

## Purpose

Ship a feature/chore/fix branch to `main` following JMo Security project policy as documented in `.claude/rules/release.rules.md` and the post-v1.0.3 stabilization memory:

- **PR-direct-to-main** — no `dev` staging hop. v1.0.3 had 41 commits drift on `dev` for 11 days requiring reconciliation PR #339.
- **Squash-merge style** — recent practice (PRs #358 onward) consolidates feature-branch commits into one main commit with `(#NNN)` suffix.
- **`dev` mirrors `main`** — invariant maintained by syncing `dev` from `main` immediately after every merge.
- **Atomic remote cleanup** — `gh pr merge --delete-branch` removes the remote branch atomically with merge. Note it also attempts a *local* delete, which fails when a worktree holds the branch — see Step 8.
- **CI is a hard gate** — never merge red CI without explicit user override.
- **Worktrees are the norm here, not the exception** — the primary checkout is shared with an always-on peer agent, so branch work happens in linked worktrees. Steps 2 and 8 both need adjusting for that; each says how.
- **Read logs, not ticks, for jobs marked `continue-on-error`** — `ci.yml`'s `windows-2022` shard is non-blocking, so `gh pr checks` reports **pass** over a real failure. Before merging anything that could plausibly affect Windows, open that job's log and compare `N passed / N skipped` against `main`. A shifted *skip* count is as much a signal as a failure — that is how a silently-uncollected 120-test suite was caught in PR #683.

## When to Use

- Feature/chore/fix work is committed on a branch other than `main` or `dev`.
- Working tree is clean, no uncommitted changes.
- Ready to ship to `main` (i.e., not mid-development).

## When NOT to Use

- On `main` or `dev` (those don't get PR'd to themselves — abort).
- During an in-flight release tag push (the release workflow has its own PR-creation step in `prepare-release`).
- When the branch is empty (`main..HEAD` shows zero commits).
- When `dev` has diverged from `main` significantly — needs a reconciliation merge (see PR #339), not a fast-forward.

## Workflow Steps

### Step 1: Preflight checks

```bash
# Refuse to ship from main or dev
BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$BRANCH" = "main" ] || [ "$BRANCH" = "dev" ]; then
  echo "ERROR: cannot ship from $BRANCH; create a feature branch first"; exit 1
fi

# Refuse on dirty tree
if [ -n "$(git status --porcelain)" ]; then
  echo "ERROR: uncommitted changes; commit or stash first"; exit 1
fi

# Refuse on empty branch
COMMITS_AHEAD=$(git rev-list --count main..HEAD)
if [ "$COMMITS_AHEAD" = "0" ]; then
  echo "ERROR: no commits ahead of main; nothing to ship"; exit 1
fi

# Verify versions.yaml/Dockerfile/workflow consistency
python scripts/dev/update_versions.py --sync --dry-run || {
  echo "ERROR: version drift detected; run --sync first"; exit 1
}

# Run formatters/linters one last time
make fmt && make lint  # (or python -m black + ruff if make unavailable)
```

### Step 2: Push branch

```bash
git push -u origin "$BRANCH"
```

If the remote branch already exists with diverged history, abort and ask the user — never `--force-with-lease` automatically.

### Step 3: Open PR

```bash
# Generate PR body from CHANGELOG [Unreleased] + commit log between main..HEAD
PR_BODY=$(cat <<EOF
## Summary

$(awk '/^## \[Unreleased\]/,/^## \[/' CHANGELOG.md | head -50 | tail -n +2 | head -n -1)

## Commits

$(git log --oneline main..HEAD)

## Test plan

- [ ] CI sharded tests pass
- [ ] yamllint / actionlint clean
- [ ] No new coverage regressions
EOF
)

gh pr create --base main --title "$PR_TITLE" --body "$PR_BODY"
```

If `$PR_TITLE` not provided as skill argument, default to the most recent commit subject.

### Step 4: Watch CI to completion

```bash
PR_NUM=$(gh pr view --json number -q .number)

# Run in background to avoid burning cache window during 12-18 min CI runs
gh pr checks "$PR_NUM" --watch --interval 60
```

**The watch process exits with**:
- `0` — all required checks passed
- non-zero — at least one required check failed

Skipping/optional checks (e.g., "Auto-update tool versions") don't affect the exit code.

### Step 5: Abort on CI failure (do NOT merge red CI)

```bash
if [ "$WATCH_EXIT" != "0" ]; then
  echo "❌ CI failed. Failed checks:"
  gh pr checks "$PR_NUM" --json name,state,link -q '.[] | select(.state == "FAILURE") | "\(.name): \(.link)"'
  echo ""
  echo "Fix locally, push to same branch, re-run /merge-pr."
  exit 1
fi
```

Never merge a red PR via this skill. If the user wants to override (e.g., flaky test that's already triaged), they should `gh pr merge` manually with explicit acknowledgement.

### Step 6: Squash-merge with remote branch deletion

```bash
gh pr merge "$PR_NUM" --squash --delete-branch
```

The `--delete-branch` flag handles remote cleanup atomically. After this:
- The PR is closed and merged.
- `origin/$BRANCH` is deleted.
- `main` has one new commit: the squashed change-set with `(#$PR_NUM)` suffix.

### Step 7: Sync dev from main

Sync `dev` **server-side, without switching any branch.** The primary checkout is shared with an always-on peer agent, so `git checkout` here would yank the branch out from under it — the same hazard Step 8 warns about.

```bash
git fetch origin

# Sanity check: dev hasn't diverged during the wait
DIVERGE=$(git rev-list --count origin/main..origin/dev)
if [ "$DIVERGE" != "0" ]; then
  echo "WARNING: dev has $DIVERGE commits not on main."
  echo "This skill won't fast-forward dev when it has unique commits."
  echo "Manual resolution required (see PR #339 reconciliation pattern)."
  exit 1
fi

# Fast-forward origin/dev to origin/main directly. Git refuses a non-fast-forward
# push by default, so this carries the same guarantee as `git merge --ff-only`
# without ever checking anything out.
git push origin origin/main:dev
```

The non-fast-forward refusal is critical — it prevents accidental merge commits if dev silently diverged. If dev had unique commits (e.g. long-running experimental work), the push is rejected and the user resolves manually.

If you happen to be on `dev` already in a checkout nobody else shares, `git merge --ff-only origin/main && git push origin dev` is equivalent. Prefer the server-side form when in doubt — it is correct in both cases.

### Step 8: Local branch cleanup

**Check for a worktree first.** Git refuses to delete a branch that any worktree holds, so on a worktree-based flow `git branch -D` exits 1 *after* the merge has already succeeded — an alarming non-zero exit for a step that is pure cleanup. Remove the worktree before the branch.

```bash
# 1. Is $BRANCH checked out in a linked worktree?
WT=$(git worktree list --porcelain \
     | awk -v b="refs/heads/$BRANCH" '/^worktree /{w=$2} /^branch /{if($2==b) print w}')

if [ -n "$WT" ]; then
  # NEVER remove a worktree blind. Confirm it holds nothing unpushed first.
  git -C "$WT" status --porcelain          # must be empty
  git -C "$WT" stash list                  # must be empty
  # origin/main, NOT main -- a worktree-based checkout often has no local main ref,
  # and `git diff main ...` then dies with "unknown revision", which reads as a
  # failed safety check when it is actually a missing one.
  git diff --quiet origin/main "$BRANCH" \
    && echo "safe: squash absorbed the tree" \
    || echo "STOP: $BRANCH still differs from origin/main"

  git worktree remove "$WT"   # add --force only after the checks above pass
fi

# 2. Now the branch is deletable
git branch -D "$BRANCH"  # force-delete needed because squash != merge

# 3. Prune the now-stale origin/$BRANCH ref
git remote prune origin
git worktree prune
```

Force-delete (`-D`) is required — `git branch -d` (lowercase) refuses to delete branches that aren't strictly merged into HEAD. With squash-merge style, the squashed commit on main has a different SHA than the feature-branch tip, so git considers the branch "unmerged" by SHA. The `-D` flag is the standard workaround.

**Do not `git checkout main` to escape the worktree problem.** In this repo the primary checkout is shared with an always-on peer agent; switching its branch out from under that agent is worse than a failed cleanup step. Remove the worktree instead, and leave the primary checkout on whatever branch it was on.

### Step 9: Summary

```bash
echo "✅ PR #$PR_NUM merged to main"
echo "✅ dev synced (now at $(git -C . rev-parse --short origin/dev))"
echo "✅ Local branch $BRANCH deleted"
echo ""
echo "Next steps:"
echo "  - If this completes a release-worthy change-set, consider:"
echo "    gh workflow run release.yml --ref main -f version_bump=patch"
echo "  - Otherwise, branch off main for the next change-set."
```

## Failure Modes

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| `cannot ship from main/dev` | Skill invoked on the wrong branch | `git checkout -b feature/<name>` first |
| `version drift detected` | `versions.yaml` was bumped without `--sync` | Run `python scripts/dev/update_versions.py --sync`, commit, retry |
| `no commits ahead of main` | Branch was already merged or never had commits | Nothing to do |
| `gh pr create` fails with "no commits between..." | Branch already in PR, or already merged | `gh pr view` to inspect; the skill probably ran already |
| CI `--watch` exits 1 with all checks shown as `pending` | Network/`gh` auth issue, not real CI failure | `gh auth status`, retry the watch |
| `dev has N commits not on main` | Someone pushed to dev between steps 6 and 7 | Manual resolve — but do it in a **worktree**, not by checking out `dev` in the shared primary tree: `git worktree add -d <tmp> origin/dev`, reconcile there, push, remove |
| `git push origin origin/main:dev` rejected as non-fast-forward | Same cause as the row above — dev gained unique commits | Same fix. The rejection is the safety net working; never `--force` it |
| `git branch -D` says "branch not found" | Already cleaned up | Idempotent; safe to ignore |
| `gh pr merge --delete-branch` exits 1 with `cannot delete branch ... used by worktree` | **The merge already succeeded.** Only the local-branch delete failed, because a linked worktree holds the branch | Not an error to fix — finish Step 8's worktree removal, then `git branch -D`. Verify the merge landed (`gh pr view <N> --json state`) before assuming anything went wrong |
| Local `make fmt && make lint` in Step 2 lints the wrong code | The working tree is on `dev`/`main`, not the feature branch (normal when the branch lives in a worktree) | Run them **in the worktree** (`cd "$WT" && make fmt lint`), or skip and rely on CI — which ran the full pre-commit suite against the actual PR head. State which you did |

## Examples

### Basic ship — no arguments

```text
/merge-pr
```

Uses the most recent commit subject as the PR title; pulls body from CHANGELOG [Unreleased].

### Override PR title

```text
/merge-pr "fix(ci): branch coverage merge for v1.0.5"
```

### Cut a release tag immediately after merge

This skill stops at "PR merged + dev synced + local cleaned up." For release-cutting, follow with:

```bash
gh workflow run release.yml --ref main \
  -f version_bump=patch \
  -f changelog_entry="<summary>"
```

The release workflow's `prepare-release` job opens its own PR for the version-bump commit. Merging that triggers the actual `v*` tag push and Docker rebuilds.

## Project Policy Encoded

This skill operationalizes these documented project rules:

- **No dev staging** — `dev` is a mirror of `main`, not a buffer ([memory: dev↔main divergence post-v1.0.3](../../../memory/v1.0.3-release-stabilization-2026-04-26.md)).
- **Squash merge style** — verified by inspecting recent merges: `(#NNN)` suffix, no "Merge pull request" prefix.
- **CI as hard gate** — `.claude/rules/release.rules.md`: *"Hotfix to main: Must go through a PR (GitHub rulesets enforce quick-checks). Cannot push directly."*
- **Version-drift preflight** — `versions.yaml` is the SSOT; Dockerfiles + workflow `env:` blocks must agree.

## See Also

- `.claude/rules/release.rules.md` — full release pipeline and troubleshooting
- `.claude/rules/testing.cross-platform.rules.md` — Workflow Marker Filter Convention used in CI
- [`jmo-ci-debugger`](../jmo-ci-debugger/SKILL.md) — invoke when CI fails and you need to diagnose
