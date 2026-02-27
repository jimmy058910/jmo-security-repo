# Repository Housekeeping Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Push unpushed commits, merge main into dev (resolve PR #185 conflicts), fix 2 CI test failures, close resolved issue #187, update 4 tool versions, and normalize GitHub Actions versions.

**Architecture:** Sequential housekeeping — git operations first (push, merge), then code fixes (CI tests), then version bumps (tools + actions), then issue cleanup. Each task is independently committable.

**Tech Stack:** Git, GitHub CLI (`gh`), pytest, versions.yaml, GitHub Actions YAML

---

### Task 1: Push 7 Unpushed Commits to origin/dev

**Files:** None (git operation only)

**Step 1: Push to remote**

```bash
git push origin dev
```

Expected: 7 commits pushed successfully. `origin/dev` now matches local `dev`.

**Step 2: Verify push**

```bash
git log --oneline origin/dev..HEAD
```

Expected: No output (no divergence).

---

### Task 2: Merge main into dev (Resolve PR #185 Conflicts)

**Files:** `.github/workflows/*.yml` (conflict resolution — accept main's dependabot versions)

Main has 6 merged dependabot PRs that dev needs:
- actions/checkout v5 -> v6
- actions/download-artifact v6 -> v7
- actions/cache v4 -> v5
- reviewdog/action-actionlint v1.68.0 -> v1.69.1
- codecov/codecov-action update
- alpine 3.22 -> 3.23

**Step 1: Merge main into dev**

```bash
git merge origin/main --no-edit
```

Expected: Merge conflicts in workflow files and possibly Dockerfiles.

**Step 2: Resolve conflicts**

For each conflicting file, accept main's newer action versions since they're the dependabot upgrades we want. Dev's structural changes to workflow files should be preserved.

Strategy per file:
- `.github/workflows/ci.yml` — accept main's action version bumps (checkout v6, cache v5, download-artifact v7, reviewdog v1.69.1, codecov update), keep dev's structural changes
- `.github/workflows/*.yml` — same pattern for other workflow files
- `Dockerfile.alpine` / packaging — accept main's alpine 3.23, keep dev's restructured paths

**Step 3: Run tests to verify merge**

```bash
make test-fast
```

Expected: Tests pass (except the 2 known CI failures we fix in Task 3).

**Step 4: Commit merge**

The merge commit is created automatically by `git merge`. If conflicts required manual resolution:

```bash
git add <resolved files>
git commit
```

---

### Task 3: Fix CI Test Failure — test_profile_thread_override

**Files:**
- Modify: `tests/integration/test_cli_profiles.py:608`

**Root Cause:** Test is missing `@pytest.mark.requires_tools` marker. All other `test_profile_*` tests (lines 376, 420, 482, 545) have this marker. CI runs with `-m "not smoke and not requires_tools"` which skips marked tests, but this test runs and fails because no security tools are installed in CI.

**Step 1: Write verification test (confirm failure)**

```bash
python -m pytest tests/integration/test_cli_profiles.py::test_profile_thread_override --co -q
```

Expected: Test is collected (not filtered out), confirming the marker is missing.

**Step 2: Add the missing marker**

In `tests/integration/test_cli_profiles.py`, add `@pytest.mark.requires_tools` before `def test_profile_thread_override`:

```python
@pytest.mark.requires_tools
def test_profile_thread_override(tmp_path: Path):
```

**Step 3: Verify test is now filtered**

```bash
python -m pytest tests/integration/test_cli_profiles.py -m "not requires_tools" --co -q | grep thread_override
```

Expected: No output (test is filtered out by the marker).

**Step 4: Commit**

```bash
git add tests/integration/test_cli_profiles.py
git commit -m "fix(tests): add missing requires_tools marker to test_profile_thread_override

Test was failing in CI on all platforms because it runs a real scan
requiring trufflehog/semgrep but CI has no security tools installed.
All other test_profile_* tests already had this marker.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 4: Fix CI Test Failure — test_sample_targets_exist

**Files:**
- Modify: `tests/integration/test_tool_contracts.py:375-387`

**Root Cause:** The trufflehog contract references `sample_target: "secrets-exposed"`, but `.gitignore:129` has pattern `*secret*` which prevents `tests/fixtures/samples/secrets-exposed/` from being committed. The directory exists locally but never reaches CI.

**Two options — pick one:**

**Option A (Recommended): Rename directory to avoid gitignore pattern**
- Rename `tests/fixtures/samples/secrets-exposed/` to `tests/fixtures/samples/credential-patterns/`
- Update the contract in `test_tool_contracts.py` line 86: `"sample_target": "credential-patterns"`
- The file contains only synthetic/fake test data (verified: AWS EXAMPLE keys, ghp_xxx placeholders)

**Option B: Add gitignore negation**
- Add `!tests/fixtures/samples/secrets-exposed/` to `.gitignore` after the `*secret*` rule
- Risk: pre-commit `detect-private-key` hook may flag the fake RSA key pattern in `config.py`

**Using Option A:**

**Step 1: Rename the fixture directory**

```bash
# Force-add the directory first (override gitignore), then rename
git mv won't work for untracked dirs, so:
mv tests/fixtures/samples/secrets-exposed tests/fixtures/samples/credential-patterns
```

Wait — the dir is gitignored and untracked. Simply rename it:

```bash
mv tests/fixtures/samples/secrets-exposed tests/fixtures/samples/credential-patterns
git add tests/fixtures/samples/credential-patterns/
```

Verify it's tracked: `git status` should show the new directory as staged.

**Step 2: Update the contract**

In `tests/integration/test_tool_contracts.py` line 86, change:

```python
"sample_target": "secrets-exposed",
```
to:
```python
"sample_target": "credential-patterns",
```

**Step 3: Run the specific test**

```bash
python -m pytest tests/integration/test_tool_contracts.py::TestContractInfrastructure::test_sample_targets_exist -v
```

Expected: PASS

**Step 4: Commit**

```bash
git add tests/fixtures/samples/credential-patterns/ tests/integration/test_tool_contracts.py
git commit -m "fix(tests): rename secrets-exposed fixture to avoid gitignore pattern

The *secret* gitignore pattern prevented tests/fixtures/samples/secrets-exposed/
from reaching CI, causing test_sample_targets_exist to fail.
Renamed to credential-patterns/ (contains only synthetic test data).

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 5: Close Issue #187 (bandit already at 1.9.3)

**Files:** None (GitHub operation only)

**Step 1: Close the issue**

```bash
GH_TOKEN= gh issue close 187 --comment "Already at v1.9.3 in versions.yaml. No action needed."
```

Note: Must unset GH_TOKEN to use keyring auth (invalid GH_TOKEN env var overrides valid keyring token).

---

### Task 6: Update 4 Tool Versions in versions.yaml

**Files:**
- Modify: `versions.yaml` (4 version bumps)
- Modify: `Dockerfile`, `Dockerfile.fast`, `Dockerfile.slim`, `Dockerfile.balanced` (via --sync)

Version updates:

| Tool | Current | Target | Issue |
|------|---------|--------|-------|
| ruff | 0.15.1 | 0.15.2 | #188 |
| falcoctl | 0.11.4 | 0.12.2 | #189 |
| nuclei | 3.5.1 | 3.7.0 | #190 |
| afl++ | 4.34c | 4.35c | #191 |

**Step 1: Update versions.yaml manually**

In `versions.yaml`:
- Line 22: `version: 0.15.1` -> `version: 0.15.2` (ruff)
- Line 124: `version: 0.11.4` -> `version: 0.12.2` (falcoctl)
- Line 144: `version: 3.5.1` -> `version: 3.7.0` (nuclei)
- Line 220: `version: 4.34c` -> `version: 4.35c` (afl++)

**Step 2: Sync Dockerfiles**

```bash
python scripts/dev/update_versions.py --sync
```

Expected: Dockerfiles updated with new versions for ruff, nuclei, falcoctl.

**Step 3: Verify Dockerfile changes**

```bash
git diff --stat
```

Expected: versions.yaml + Dockerfiles modified with correct version strings.

**Step 4: Commit**

```bash
git add versions.yaml Dockerfile Dockerfile.fast Dockerfile.slim Dockerfile.balanced
git commit -m "chore(deps): update ruff 0.15.2, falcoctl 0.12.2, nuclei 3.7.0, afl++ 4.35c

Closes #188, closes #189, closes #190, closes #191

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 7: Normalize GitHub Actions Versions on dev

**Files:**
- Modify: `.github/workflows/docker-validation.yml` (upload-artifact v4 -> v5, download-artifact v4 -> v5)

Note: After Task 2 (merge main), dev will have the dependabot upgrades. But `docker-validation.yml` was already behind (v4 vs v5) even before the dependabot PRs. This task catches it up.

**Step 1: Update docker-validation.yml**

Line 149: `actions/upload-artifact@v4` -> `actions/upload-artifact@v5`
Line 174: `actions/download-artifact@v4` -> `actions/download-artifact@v5`

**Step 2: Verify no other stale versions**

```bash
grep -rn "actions/upload-artifact@v4\|actions/download-artifact@v4\|actions/cache@v3\|actions/checkout@v4" .github/workflows/
```

Expected: No output (all normalized).

**Step 3: Commit**

```bash
git add .github/workflows/docker-validation.yml
git commit -m "chore(ci): normalize docker-validation action versions to v5

upload-artifact and download-artifact were still at v4 while all
other workflows use v5.

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 8: Push All Changes and Verify PR #185

**Files:** None (git operations only)

**Step 1: Push dev to remote**

```bash
git push origin dev
```

**Step 2: Verify PR #185 merge status**

```bash
GH_TOKEN= gh pr view 185 --json mergeStateStatus,mergeable
```

Expected: `mergeable: MERGEABLE`, `mergeStateStatus: CLEAN` (or `BLOCKED` if CI hasn't run yet).

**Step 3: Wait for CI to pass**

Monitor CI status. The two test failures should now be fixed.

---

## Summary

| Task | Type | Estimated |
|------|------|-----------|
| 1. Push 7 commits | Git | 1 min |
| 2. Merge main into dev | Git + conflict resolution | 5-10 min |
| 3. Fix test_profile_thread_override | Code fix (1 line) | 2 min |
| 4. Fix test_sample_targets_exist | Code fix + rename | 5 min |
| 5. Close issue #187 | GitHub | 1 min |
| 6. Update 4 tool versions | Config + sync | 5 min |
| 7. Normalize action versions | YAML fix | 2 min |
| 8. Push and verify | Git | 2 min |
