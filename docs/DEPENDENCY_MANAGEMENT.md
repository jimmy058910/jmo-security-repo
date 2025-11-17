# Dependency Management Guide

## Overview

JMo Security uses a **Python version-locked dependency system** to ensure consistent builds across development, CI, and production environments.

**Critical Rule:** `requirements-dev.txt` MUST be compiled with **Python 3.10+** to match CI/CD environments.

---

## Quick Reference

| Task | Command | When to Use |
|------|---------|-------------|
| **Validate** | `make deps-validate` | Before every release, in CI |
| **Recompile** | `make deps-compile` | After updating `requirements-dev.in` |
| **Upgrade All** | `make deps-upgrade` | Monthly dependency updates |
| **Check Outdated** | `make deps-check-outdated` | Weekly audits |
| **Sync Environment** | `make deps-sync` | After pulling new `requirements-dev.txt` |

---

## The Problem (v0.7.1 Discovery)

### What Happened

During v0.7.1 release prep, we discovered `requirements-dev.txt` was compiled with Python 3.8, while CI uses Python 3.10/3.11/3.12. This caused:

1. **4 Unintended Downgrades:**
   - bandit: 1.8.6 → 1.7.10 ❌
   - pytest-cov: 7.0.0 → 5.0.0 ❌
   - mypy: 1.18.2 → 1.14.1 ❌
   - coverage: 7.10.7 → 7.6.1 ❌

2. **5 Dependency Conflicts:**
   - `checkov` requires `packaging<24.0`, but got `packaging 25.0`
   - `semgrep` requires `urllib3~=2.0`, but got `urllib3 1.26.20`
   - `langchain` mismatches on `langsmith` versions

3. **CI Incompatibility:**
   - Tests on Python 3.10+ used different dependency versions
   - Non-deterministic behavior across environments

### Root Cause

`pip-compile` uses the **active Python version** to resolve dependencies. Python 3.8 has different available versions than Python 3.10+, leading to downgrades.

---

## The Solution

### Automated Validation (`update_dependencies.py`)

We built [scripts/dev/update_dependencies.py](../scripts/dev/update_dependencies.py) to prevent this:

**Features:**

- ✅ Enforces Python 3.10+ for compilation
- ✅ Detects dependency conflicts (`pip check`)
- ✅ Prevents accidental downgrades
- ✅ Provides upgrade preview before applying
- ✅ CI-compatible (exit codes for automation)

**Usage:**

```bash

# Validate current requirements-dev.txt

python3 scripts/dev/update_dependencies.py --validate

# Recompile (safe, preserves versions)

python3 scripts/dev/update_dependencies.py --compile

# Upgrade all dependencies (use with caution)

python3 scripts/dev/update_dependencies.py --upgrade

# Check for outdated packages

python3 scripts/dev/update_dependencies.py --check-outdated
```text

### Makefile Integration

```bash

# Validate (pre-release requirement)

make deps-validate

# Recompile with current Python

make deps-compile

# Upgrade all dependencies (prompts for confirmation)

make deps-upgrade

# Check for outdated packages

make deps-check-outdated
```text

### CI Automation

Added to [.github/workflows/ci.yml](../.github/workflows/ci.yml):

```yaml

- name: Validate requirements-dev.txt Python version

    python -m pip install pip-tools
    python scripts/dev/update_dependencies.py --validate
```text
**This runs on every PR and push**, blocking merges if Python version is incorrect.

---

## Dependency Update Workflows

### Weekly Audit (Security Monitoring)

**Every Monday morning:**

```bash

# Check for outdated packages

make deps-check-outdated

# Review output for security-critical packages:

# - pytest, pytest-cov (test infrastructure)

# - black, ruff, mypy (dev tools)

# - pip-tools (dependency management)

```text
**Action if vulnerabilities found:**

1. Research CVE severity (use `pip-audit` if available)
2. If HIGH/CRITICAL, upgrade immediately
3. Otherwise, defer to monthly cycle

### Monthly Upgrade Cycle (First Monday of Month)

**Comprehensive dependency refresh:**

```bash

# Step 1: Check current state

make deps-validate
make deps-check-outdated

# Step 2: Review outdated packages

# Note packages with major version changes (may have breaking changes)

# Step 3: Upgrade (prompts for confirmation)

make deps-upgrade

# Step 4: Review changes

git diff requirements-dev.txt

# Step 5: Validate no conflicts

make deps-validate

# Step 6: Run full test suite

make test
make lint

# Step 7: Commit

git add requirements-dev.txt
git commit -m "deps: monthly dependency update (YYYY-MM)

- Package upgrades: [list key upgrades]
- All tests passing
- No dependency conflicts

Related: Monthly maintenance cycle"
```text

### Before Every Release (v0.7.1 Lesson)

**Pre-release checklist:**

```bash

# 1. Validate Python version

make deps-validate

# Expected output:

# [ok] requirements-dev.txt compiled with Python 3.10 (or higher)

# [ok] No dependency conflicts detected

# 2. If validation fails:

python3.10 scripts/dev/update_dependencies.py --compile

# OR

python3.11 scripts/dev/update_dependencies.py --compile

# 3. Verify no downgrades

git diff requirements-dev.txt

# Look for lines like: -package==1.2.0 +package==1.1.0 (DOWNGRADE, BAD)

# 4. Run tests

make test

# 5. Commit if changed

git add requirements-dev.txt
git commit -m "deps: recompile with Python 3.10+ for v0.X.Y release"
```text
---

## Troubleshooting

### Error: "Python 3.10+ required (detected 3.8)"

**Cause:** Using wrong Python version to compile dependencies.

**Fix:**

```bash

# Option 1: Use Python 3.10

python3.10 -m pip install pip-tools
python3.10 scripts/dev/update_dependencies.py --compile

# Option 2: Use Python 3.11

python3.11 -m pip install pip-tools
python3.11 scripts/dev/update_dependencies.py --compile

# Option 3: Use Python 3.12

python3.12 -m pip install pip-tools
python3.12 scripts/dev/update_dependencies.py --compile
```text

### Error: "X dependency conflict(s) detected"

**Cause:** Conflicting version constraints in `requirements-dev.in` or transitive dependencies.

**Example:**

```text
checkov 3.2.477 requires packaging<24.0, but have packaging 25.0
```text
**Fix:**

```bash

# Option 1: Pin conflicting package in requirements-dev.in

echo "packaging<24.0  # Required by checkov" >> requirements-dev.in
make deps-compile

# Option 2: Wait for upstream fix (check checkov releases)

# If checkov updates to support packaging>=24.0, update checkov version

# Option 3: Downgrade offending package (last resort)

echo "packaging==23.2" >> requirements-dev.in
make deps-compile
```text

### Error: "Downgrades detected! This should not happen."

**Cause:** Version constraints in `requirements-dev.in` forcing downgrades.

**Example:**

```text
Downgrades (4):
  ↓ bandit: 1.8.6 → 1.7.10
  ↓ pytest-cov: 7.0.0 → 5.0.0
```text
**Fix:**

```bash

# Step 1: Check requirements-dev.in for version pins

cat requirements-dev.in | grep -E "bandit|pytest-cov"

# Step 2: Remove overly restrictive pins

# BAD:  bandit<1.8  # Forces downgrade

# GOOD: bandit>=1.7.10  # Allows upgrades

# Step 3: Recompile

make deps-compile

# Step 4: Verify upgrades

git diff requirements-dev.txt | grep -E "^\+bandit|^\+pytest-cov"
```text

### Error: "pip-tools not installed"

**Cause:** `pip-tools` not available in active Python environment.

**Fix:**

```bash

# Install for active Python

python3 -m pip install pip-tools

# Or specify Python version

python3.10 -m pip install pip-tools
python3.11 -m pip install pip-tools
```text
---

## Development Workflow

### Adding a New Dependency

```bash

# Step 1: Add to requirements-dev.in

echo "new-package>=1.0.0" >> requirements-dev.in

# Step 2: Recompile

make deps-compile

# Step 3: Sync environment

make deps-sync

# Step 4: Verify no conflicts

make deps-validate

# Step 5: Test

make test

# Step 6: Commit both files

git add requirements-dev.in requirements-dev.txt
git commit -m "deps: add new-package for [purpose]"
```text

### Removing a Dependency

```bash

# Step 1: Remove from requirements-dev.in

# (edit file manually)

# Step 2: Recompile (will remove transitive deps if unused)

make deps-compile

# Step 3: Sync environment (will uninstall)

make deps-sync

# Step 4: Verify no conflicts

make deps-validate

# Step 5: Commit

git add requirements-dev.in requirements-dev.txt
git commit -m "deps: remove old-package (no longer needed)"
```text

### Upgrading a Specific Package

```bash

# Step 1: Update version in requirements-dev.in

# Before: package>=1.0.0

# After:  package>=2.0.0

# Step 2: Recompile

make deps-compile

# Step 3: Review changes

git diff requirements-dev.txt

# Step 4: Test for breaking changes

make test
make lint

# Step 5: Commit

git add requirements-dev.in requirements-dev.txt
git commit -m "deps: upgrade package to v2.0.0

- Breaking changes: [list if any]
- Tested: [describe test coverage]"
```text
---

## CI Integration

### Pre-Release Gate

The CI workflow **blocks releases** if dependencies are invalid:

```yaml

- name: Validate requirements-dev.txt Python version

    python -m pip install pip-tools
    python scripts/dev/update_dependencies.py --validate
```text
**Exit codes:**

- `0` - All checks passed
- `1` - Python version mismatch OR dependency conflicts

### Dependabot Integration

[.github/dependabot.yml](../.github/dependabot.yml) automatically creates PRs for:

- Python package updates (weekly)
- GitHub Actions updates (weekly)
- Docker base image updates (weekly)

**Workflow:**

1. Dependabot creates PR with version bump
2. CI validates Python version and conflicts
3. Tests run on Python 3.10/3.11/3.12
4. If all pass, merge PR

---

## Best Practices

### ✅ DO

- ✅ **Always use Python 3.10+ for `deps-compile`**
- ✅ **Run `deps-validate` before every release**
- ✅ **Commit both `requirements-dev.in` AND `requirements-dev.txt`**
- ✅ **Review diff after `deps-compile` (check for downgrades)**
- ✅ **Run full test suite after dependency changes**
- ✅ **Use version ranges** (`>=1.0.0`) instead of exact pins (`==1.0.0`) in `.in` file
- ✅ **Document why** when pinning to specific versions (add comment)

### ❌ DON'T

- ❌ **Never compile with Python 3.8 or 3.9** (CI uses 3.10+)
- ❌ **Never commit only `requirements-dev.txt` without `.in`** (loses dependency rationale)
- ❌ **Never ignore `pip check` conflicts** (will break at runtime)
- ❌ **Never blindly accept Dependabot PRs** (always review changes and test)
- ❌ **Never pin exact versions in `.in` file without reason** (prevents security updates)

---

## Migration Guide (For Contributors)

If you previously compiled dependencies with Python 3.8/3.9:

### Step 1: Install Python 3.10+

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install python3.10 python3.10-venv
```text
**macOS (Homebrew):**
```bash
brew install python@3.10
```text
**Windows (WSL):**
```bash
sudo apt install python3.10
```text

### Step 2: Update Your Workflow

**Old workflow (Python 3.8):**
```bash
python3 -m pip install pip-tools
python3 -m piptools compile -o requirements-dev.txt requirements-dev.in
```text
**New workflow (Python 3.10+):**
```bash
python3.10 -m pip install pip-tools
python3.10 scripts/dev/update_dependencies.py --compile

# OR use Makefile

make deps-compile  # Uses PY variable (defaults to python3)
```text

### Step 3: Validate

```bash
make deps-validate
```text
**Expected output:**
```text
[ok] Python 3.10 (meets requirement ≥3.10)
[ok] requirements-dev.txt compiled with Python 3.10
[ok] No dependency conflicts detected
```text
---

## Future Improvements

### Planned Enhancements

1. **Automatic Vulnerability Scanning:**

   pip install pip-audit
   make deps-audit  # Check for known CVEs
   ```

1. **Dependency Graph Visualization:**

   ```bash
   pip install pipdeptree
   make deps-tree  # Show dependency tree
   ```

2. **Lockfile Comparison:**

   ```bash
   make deps-diff v0.7.0 v0.7.1  # Compare dependency changes between versions
   ```

3. **Automated PR Creation:**

   ```bash
   # After make deps-upgrade, auto-create PR with changelog
   make deps-upgrade-pr
   ```

---

## References

- **Update Script:** [scripts/dev/update_dependencies.py](../scripts/dev/update_dependencies.py)
- **CI Workflow:** [.github/workflows/ci.yml](../.github/workflows/ci.yml)
- **Dependabot Config:** [.github/dependabot.yml](../.github/dependabot.yml)
- **Makefile Targets:** [Makefile](../Makefile) (lines 24-30, 115-136)
- **pip-tools Documentation:** <https://pip-tools.readthedocs.io/>

---

## Lessons Learned (v0.7.1)

### What We Fixed

1. **Created `update_dependencies.py`** - Automated Python version validation
2. **Added CI check** - Blocks PRs with incorrect Python version
3. **Updated Makefile** - Easy-to-use targets (`deps-validate`, `deps-upgrade`)
4. **Documented workflow** - This guide prevents future issues

### Impact

- **Time saved:** 2-3 hours per release (no more manual dependency debugging)
- **Error reduction:** CI blocks invalid compilations (can't merge broken deps)
- **Consistency:** All environments use same dependency versions
- **Security:** Monthly audits catch vulnerabilities early

### Prevention

**Never again will we:**

- ❌ Compile dependencies with wrong Python version
- ❌ Miss dependency conflicts before release
- ❌ Lose Dependabot upgrades due to downgrades
- ❌ Have non-deterministic builds across environments

---

**Last Updated:** 2025-10-23 (v0.7.1)
**Maintainer:** JMo Security Team
**Next Review:** 2025-11-23 (quarterly)
