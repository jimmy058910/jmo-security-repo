# Prevention Strategies (Full Reference)

Comprehensive CI best practices and prevention strategies for JMo Security.

---

## Pre-Push Checklist

Run before every push to catch issues early:

```bash
# 1. Install pre-commit hooks (one-time)
make pre-commit-install

# 2. Run all checks
make pre-commit-run

# 3. Run tests with coverage
make test

# 4. Build Docker (if modified)
docker build -t jmo-test .
docker run --rm jmo-test --help

# 5. Validate workflows (if modified)
yamllint .github/workflows/*.yml
actionlint .github/workflows/*.yml

# 6. Check requirements freshness (if modified .in files)
make deps-compile
git diff requirements-dev.txt  # Should be no changes if already compiled
```

---

## Local CI Simulation

Test CI conditions locally:

```bash
# Simulate test matrix (Python 3.10, 3.11, 3.12)
for py in 3.10 3.11 3.12; do
  docker run --rm -v $(pwd):/workspace -w /workspace python:$py-slim \
    bash -c "pip install -e .[dev] && pytest --cov --cov-fail-under=85"
done

# Simulate quick-checks
make pre-commit-run
yamllint .github/workflows/*.yml
actionlint .github/workflows/*.yml
python scripts/dev/check_requirements_fresh.py  # If exists
```

---

## Fail Fast Configuration

Optimize CI for fast feedback:

```yaml
# ci.yml
jobs:
  quick-checks:
    # Runs first, fails fast (2-3 min)
    ...

  test-matrix:
    # Only runs if quick-checks passes
    needs: quick-checks
    strategy:
      fail-fast: true  # Stop other jobs if one fails
      matrix:
        os: [ubuntu-latest, macos-latest]
        python-version: ["3.10", "3.11", "3.12"]
```

---

## Pre-commit Hook Order (Critical)

Black MUST run before Ruff. This is enforced in `.pre-commit-config.yaml`:

```yaml
repos:
  # Step 1: Format code (Black)
  - repo: https://github.com/psf/black
    hooks:
      - id: black

  # Step 2: Lint code (Ruff) -- RUNS AFTER BLACK
  - repo: https://github.com/astral-sh/ruff-pre-commit
    hooks:
      - id: ruff
        args: [--fix, --exit-non-zero-on-fix]
```

**Why this order matters:**

- **Black first**: Establishes formatting baseline
- **Ruff with --fix**: Auto-removes unused imports, optimizes f-strings
- **Ruff check-only**: Ensures all fixes applied (fail if manual intervention needed)

---

## Local Pre-Commit Discipline

```bash
# Install hooks (one-time setup)
pre-commit install

# Before EVERY push to main
pre-commit run --all-files

# Update hooks monthly
pre-commit autoupdate
```

---

## Enhanced Pre-Push Hook

Add to `.git/hooks/pre-push`:

```bash
#!/bin/bash
set -e

echo "Running pre-push checks..."

# Check for untracked Python modules
untracked=$(git ls-files --others --exclude-standard scripts/ | grep "\.py$" || true)
if [ -n "$untracked" ]; then
  echo "ERROR: Untracked Python files found in scripts/:"
  echo "$untracked"
  echo "Fix: Run 'git add scripts/' before pushing"
  exit 1
fi

# Validate critical module imports
for module in compliance_frameworks exceptions tool_runner constants; do
  if ! python3 -c "import scripts.core.$module" 2>/dev/null; then
    echo "ERROR: Cannot import scripts.core.$module"
    exit 1
  fi
done

# Run mypy on staged Python files
echo "Running mypy on staged Python files..."
STAGED_PY=$(git diff --cached --name-only | grep '\.py$' || true)
if [ -n "$STAGED_PY" ]; then
  mypy $STAGED_PY || exit 1
fi

# Run markdownlint on staged Markdown files
echo "Running markdownlint on staged Markdown files..."
STAGED_MD=$(git diff --cached --name-only | grep '\.md$' || true)
if [ -n "$STAGED_MD" ]; then
  npx markdownlint $STAGED_MD || exit 1
fi

echo "Pre-push checks passed!"
```

---

## Weekly Maintenance Routine

```bash
# Every Monday (15 minutes)
pre-commit autoupdate           # Update hook versions
pre-commit run --all-files      # Find new violations
# Fix ALL violations found
git add .pre-commit-config.yaml <fixed-files>
git commit -m "chore: weekly pre-commit maintenance"
```

---

## Technical Debt Principle

**CRITICAL: Fix ALL violations found, not just new ones.**

Why this matters:

- Prevents compound technical debt
- Future contributors don't inherit your debt
- "Boy Scout Rule": Leave code better than you found it

```bash
# Wrong: Fix only your 3 new violations
pre-commit run markdownlint --files docs/NEW_FILE.md

# Correct: Fix ALL 13 violations across all 8 files
pre-commit run markdownlint --all-files
# Must show: "Passed" for all files before committing
```

---

## Branch Strategy Best Practices

1. **Always use feature branches** - Never commit directly to main locally
2. **Test locally first** - Run full pre-flight checklist before pushing
3. **Create PR immediately** - Don't wait until "ready" - use draft PRs
4. **Monitor CI actively** - Use `gh pr checks --watch` for real-time feedback
5. **Document branch strategy** - Add to CONTRIBUTING.md for collaborators

---

## Dependabot Prevention

Configure Dependabot to run at predictable times:

```yaml
# .github/dependabot.yml
schedule:
  interval: "weekly"
  day: "monday"
  time: "09:00"
```

Install pre-push hooks that catch untracked files before they break Dependabot PRs.

---

## Cross-Platform Test Guidelines

When writing tests that may differ across platforms:

- **Floating-point similarity**: 5-10% buffer
- **Performance timing**: 20-30% buffer (hardware varies more)
- **Statistical tests**: Use confidence intervals (95% or 99%)
- **Exact values**: Use `pytest.approx(rel=0.01)` for 1% tolerance

```python
# Use pytest.approx for cross-platform float comparisons
assert similarity == pytest.approx(0.75, rel=0.05)

# Use ranges with documented rationale
MIN_SCORE = 95.0  # Observed minimum across all platforms: 96.2
MAX_SCORE = 105.0  # Observed maximum across all platforms: 103.8
assert MIN_SCORE <= score <= MAX_SCORE
```
