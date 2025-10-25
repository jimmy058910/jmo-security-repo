# CI Troubleshooting Guide

*Comprehensive guide to preventing and fixing common CI failures in JMo Security*

## Quick Diagnosis

```bash
# Check latest CI status
gh run list --limit 5

# View failed run logs
gh run view <run-id> --log-failed

# Check specific job
gh run view <run-id> --log --job=<job-id>

# Watch PR checks in real-time
gh pr checks <pr-number> --watch
```

## Common Failure Patterns

### 1. Markdownlint Failures

**Symptoms:**

```text
markdownlint.............................................................Failed
MD032/blanks-around-lists Lists should be surrounded by blank lines
MD040/fenced-code-language Fenced code blocks should have a language specified
MD036/no-emphasis-as-heading Emphasis used instead of a heading
```

**Root Cause:** Documentation doesn't follow markdown linting rules.

**Prevention:**

```bash
# ALWAYS run before committing documentation
pre-commit run markdownlint --files <changed-files>

# Or run on all markdown files
pre-commit run markdownlint --all-files
```

**Quick Fix:**

1. **Blank lines around lists (MD032):**
   - Add blank line BEFORE list starts
   - Add blank line AFTER list ends

2. **Code fence language (MD040):**
   - Change `` ``` `` to `` ```bash `` or `` ```python `` or `` ```text ``

3. **Emphasis as heading (MD036):**
   - Change `**Bold Text**` to `## Heading` OR `*italic text*` (for subtitles)

**Configuration:**

Disable false-positive rules in `.markdownlint.json`:

```json
{
  "MD036": false,  // Italics subtitles incorrectly flagged
  "MD051": false,  // Valid internal anchors incorrectly flagged
  "MD024": {"siblings_only": true}  // Allow duplicate headings in CHANGELOG
}
```

---

### 2. Requirements Drift (deps-compile freshness)

**Symptoms:**

```text
requirements-dev.txt is out of date. Run: make deps-compile
diff --git a/requirements-dev.txt b/requirements-dev.txt
-#    pip-compile --output-file=/home/user/repo/requirements-dev.txt
+#    pip-compile --output-file=requirements-dev.txt
```

**Root Cause:** Local `pip-compile` uses absolute paths, CI uses relative paths.

**Prevention:**

```bash
# NEVER commit requirements-dev.txt with absolute paths
# Check for absolute paths:
grep "/home/" requirements-dev.txt && echo "❌ Absolute paths detected!"

# Regenerate with relative paths:
pip-compile --output-file=requirements-dev.txt requirements-dev.in
```

**Quick Fix:**

```bash
# Revert to CI's version
git checkout origin/main -- requirements-dev.txt

# OR regenerate locally with correct format
make deps-compile
git diff requirements-dev.txt  # Should show NO absolute paths
```

**Permanent Solution:**

Add to pre-commit hook (`.pre-commit-config.yaml`):

```yaml
  - id: deps-compile
    name: deps-compile (validate Python 3.10+ and generate requirements-dev.txt)
    entry: bash -c 'python3 scripts/dev/update_dependencies.py --validate'
    language: system
    files: requirements-dev\.(in|txt)$
    pass_filenames: false
```

---

### 3. Gitignore Pattern Issues

**Symptoms:**

```text
.jmo/memory/refactoring/phase-4-detailed-plan.md:12 MD032/blanks-around-lists
.jmo/memory/testing/wizard-test-coverage-session.json
```

**Root Cause:** Files that should be ignored are tracked in git.

**Prevention:**

```bash
# Check if file SHOULD be ignored
git check-ignore -v <file>

# If yes, remove from tracking:
git rm --cached <file>
git commit -m "fix(gitignore): remove incorrectly tracked file"
```

**Common Patterns:**

```gitignore
# ❌ WRONG - allows subdirectory contents
.jmo/memory/*
!.jmo/memory/*/

# ✅ CORRECT - blocks all content files
.jmo/memory/**/*
!.jmo/memory/.gitkeep
!.jmo/memory/README.md
!.jmo/memory/**/.gitkeep
```

---

### 4. Pre-commit Hook Version Drift

**Symptoms:**

```text
[WARNING] repo `https://github.com/pre-commit/pre-commit-hooks` uses deprecated stage names
ruff....................................Failed
shellcheck..............................Failed
```

**Root Cause:** Pre-commit hooks outdated or environment mismatch.

**Prevention:**

```bash
# Update hooks regularly (monthly)
pre-commit autoupdate

# Test after update
pre-commit run --all-files

# Commit if successful
git add .pre-commit-config.yaml
git commit -m "build(deps): update pre-commit hooks"
```

**Quick Fix:**

```bash
# Clean pre-commit cache
pre-commit clean
pre-commit install --install-hooks
pre-commit run --all-files
```

---

### 5. Test Coverage Below Threshold

**Symptoms:**

```text
FAILED: Coverage of 82% is below threshold of 85%
```

**Root Cause:** New code not sufficiently tested.

**Prevention:**

```bash
# Check coverage before committing
pytest --cov --cov-report=term-missing

# Focus on uncovered lines
pytest --cov --cov-report=html
open htmlcov/index.html
```

**Quick Fix:**

1. Identify uncovered lines from report
2. Write tests for those code paths
3. Test error handling, edge cases, v1.1.0/v1.2.0 features
4. Aim for >90% (buffer below 85% threshold)

---

### 6. Actionlint Failures

**Symptoms:**

```text
.github/workflows/ci.yml:45:7: unexpected input 'fail_on_error' [syntax-check]
```

**Root Cause:** Using deprecated or incorrect action parameters.

**Prevention:**

```bash
# Validate workflows before committing
actionlint .github/workflows/*.yml

# Or via pre-commit
pre-commit run actionlint --files .github/workflows/ci.yml
```

**Common Fixes:**

- `fail_on_error: true` → `fail_level: error`
- Check action documentation for current parameter names
- Use `reviewdog/action-actionlint@v1` not older versions

---

### 7. Docker Build/Tag Failures

**Symptoms:**

```text
Error: invalid reference format: v0.5.0
Error: unknown flag: --version
```

**Root Causes:**

1. Docker tag includes 'v' prefix (Git tag format)
2. Testing with unsupported CLI flags

**Prevention:**

```bash
# Extract tag correctly (no 'v' prefix)
TEST_TAG=$(echo "${{ steps.meta.outputs.tags }}" | head -n1 | cut -d':' -f2)

# Test with supported flags
docker run --rm image:tag --help  # ✅ Works
docker run --rm image:tag --version  # ❌ jmo doesn't support this
```

---

## Pre-Commit Checklist

Run BEFORE every commit:

```bash
# 1. Format code
make fmt

# 2. Run linters
make lint

# 3. Run tests with coverage
make test

# 4. Run pre-commit hooks
pre-commit run --all-files

# 5. Check for absolute paths in requirements
grep -E "/home/|/Users/" requirements-dev.txt && echo "❌ Fix paths!"

# 6. Verify gitignore patterns
git status --ignored | grep ".jmo/memory/" && echo "❌ Remove from tracking!"
```

---

## CI Environment Differences

### Local vs CI

| Aspect | Local | CI (GitHub Actions) |
|--------|-------|---------------------|
| **Python Path** | `/home/user/...` | Relative paths only |
| **pip-compile** | May use absolute paths | Always uses relative |
| **pre-commit cache** | `~/.cache/pre-commit` | Fresh on every run |
| **Tools** | May have extras installed | Minimal environment |

### Makefile Targets for CI Parity

```bash
# Simulate CI environment locally
make ci-test     # Run tests as CI does
make ci-lint     # Run lints as CI does
make ci-verify   # Full CI simulation
```

---

## Emergency Fixes

### "CI is broken, need to merge urgently"

**Option 1: Skip failing checks (LAST RESORT)**

```bash
# Add to PR body:
# skip-checks: markdownlint

# Or push with --no-verify (skips pre-commit):
git push --no-verify  # ⚠️ Only for hotfixes!
```

**Option 2: Disable failing hook temporarily**

```yaml
# .pre-commit-config.yaml
  - id: markdownlint
    # Temporarily disable
    exclude: ^docs/  # Skip docs temporarily
```

**Option 3: Create bypass PR**

```bash
# Merge main first, fix later
git checkout -b hotfix/bypass-ci
git commit --allow-empty -m "chore: bypass CI for hotfix"
gh pr create --title "Hotfix: bypass CI" --label "hotfix"
# Merge immediately, then fix CI in follow-up PR
```

---

## Future Prevention

### 1. Add CI Status Badge to README

```markdown
[![CI](https://github.com/jimmy058910/jmo-security-repo/workflows/CI/badge.svg)](https://github.com/jimmy058910/jmo-security-repo/actions/workflows/ci.yml)
```

### 2. Branch Protection Rules

Required status checks:

- ✅ Quick checks
- ✅ Test ubuntu-latest / Python 3.11
- ✅ Lint (quick checks)

### 3. Pre-Push Git Hook

`.git/hooks/pre-push`:

```bash
#!/bin/bash
# Prevent push if pre-commit fails

echo "🔍 Running pre-push validation..."

# Run quick checks
make lint 2>&1 | head -20
if [ ${PIPESTATUS[0]} -ne 0 ]; then
  echo "❌ Lint failed. Fix with: make fmt && make lint"
  exit 1
fi

# Check for absolute paths
if grep -qE "/home/|/Users/" requirements-dev.txt; then
  echo "❌ Absolute paths in requirements-dev.txt"
  echo "Fix with: make deps-compile"
  exit 1
fi

echo "✅ Pre-push checks passed"
```

### 4. CI Debugging Workflow

When CI breaks repeatedly:

1. **Capture the pattern** - Document in this file
2. **Add prevention** - Pre-commit hook or Makefile check
3. **Add to jmo-ci-debugger skill** - Update `.claude/skills/jmo-ci-debugger/SKILL.md`
4. **Test locally first** - Use `make ci-verify`
5. **Update docs** - Keep this guide current

---

## Related Documentation

- [CLAUDE.md#CI/CD Common Fixes](../CLAUDE.md#cicd-common-fixes)
- [.claude/skills/jmo-ci-debugger/SKILL.md](../.claude/skills/jmo-ci-debugger/SKILL.md)
- [.github/workflows/ci.yml](../.github/workflows/ci.yml)
- [CONTRIBUTING.md#Pre-commit Hooks](../CONTRIBUTING.md#pre-commit-hooks)

---

## Success Metrics

**CI Health:**

- ✅ Green CI on main branch for 7+ days
- ✅ PR checks pass on first push (no re-runs needed)
- ✅ Pre-commit hooks catch 95%+ of issues locally

**When to Update This Guide:**

- New CI failure pattern encountered
- Preventable issue reaches CI 2+ times
- Workflow changes (new jobs, checks, requirements)

---

*Last Updated: 2025-10-24*
*Maintained By: JMo Security Contributors*
