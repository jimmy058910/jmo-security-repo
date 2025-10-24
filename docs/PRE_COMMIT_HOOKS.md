# Pre-Commit Hooks Guide

## Overview

JMo Security uses [pre-commit](https://pre-commit.com/) to enforce code quality, security, and consistency before commits reach the repository.

**Key Feature (v0.7.1+):** The `deps-compile` hook automatically re-executes with Python 3.10+ if run with an older Python version, preventing dependency version mismatches.

---

## Quick Start

### Installation

```bash
# Install pre-commit hooks
make pre-commit-install

# Run all hooks manually
make pre-commit-run

# Run specific hook
pre-commit run <hook-id> --all-files
```

### Auto-Execution

Once installed, hooks run automatically:
- **On `git commit`:** All hooks for staged files
- **On `git push`:** Pre-push checks (Python imports, critical validation)

---

## Hooks Configuration

### Active Hooks (23 total)

#### File Format Validation
1. **trailing-whitespace** — Remove trailing whitespace
2. **end-of-file-fixer** — Ensure files end with newline
3. **mixed-line-ending** — Normalize line endings (LF only)
4. **check-yaml** — Validate YAML syntax
5. **check-json** — Validate JSON syntax
6. **check-toml** — Validate TOML syntax (pyproject.toml)

#### Security
7. **detect-private-key** — Prevent committing private keys
8. **check-added-large-files** — Block files >10MB
9. **bandit** — Python security linter (scripts/ only, strict config)

#### Code Quality - Python
10. **ruff** — Fast Python linter (auto-fix enabled)
11. **black** — Python formatter (opinionated)
12. **mypy** — Type checker (scripts/ only)

#### Code Quality - Shell
13. **shellcheck** — Shell script linter
14. **shfmt** — Shell script formatter

#### Code Quality - YAML
15. **yamllint** — Strict YAML linting (schema-agnostic)

#### Code Quality - Markdown
16. **markdownlint** — Markdown linting (accessibility, rendering)

#### CI/CD Validation
17. **actionlint** — Validate GitHub Actions workflows

#### Dependency Management (v0.7.1+)
18. **deps-compile** — Auto-compile requirements-dev.txt with Python 3.10+

---

## Hook Details

### deps-compile (Critical for v0.7.1+)

**Purpose:** Ensures `requirements-dev.txt` is always compiled with Python 3.10+ to match CI/CD environments.

**Behavior:**
1. Triggers when `requirements-dev.in` is modified
2. Detects active Python version
3. If Python <3.10, **automatically re-executes with Python 3.11/3.10/3.12**
4. Compiles dependencies with correct Python version
5. Fails if no Python 3.10+ found on system

**Example Output (Auto-Reexec):**

```bash
$ git commit -m "deps: update pytest"
[warn] Python 3.8 detected, re-executing with python3.11...
[ok] Python 3.11 (meets requirement ≥3.10)
[info] Running pip-compile (will preserve existing versions if compatible)
[ok] requirements-dev.txt compiled successfully
[ok] No dependency conflicts detected
```

**Example Output (No Python 3.10+):**

```bash
$ git commit -m "deps: update pytest"
[error] Python 3.10+ required (detected 3.8)
[hint] No Python 3.10+ found on system
[hint] Install: sudo apt install python3.11  # Ubuntu/Debian
[hint] Or: brew install python@3.11  # macOS
```

**Why This Matters:**

Before v0.7.1, running `make deps-compile` with Python 3.8 would cause:
- 5 dependency conflicts
- 4 package downgrades
- CI incompatibility (CI uses Python 3.10/3.11/3.12)

Now, the hook automatically uses the correct Python version, preventing these issues.

### bandit (Security)

**Configuration:** `bandit.yaml`
- **Strict mode:** All security checks enabled
- **Skipped in tests:** B101 (assert usage), B404 (import subprocess)
- **Exit codes:** Fails on HIGH/CRITICAL findings only

**Example findings:**
- Hardcoded passwords/secrets
- SQL injection risks
- Shell injection risks
- Insecure random number generation

**False positives:** Use `# nosec` comment to suppress (with justification)

### mypy (Type Checking)

**Scope:** `scripts/` only (not tests)
- **Config:** `pyproject.toml`
- **Additional deps:** `types-PyYAML`

**Common fixes:**
- Add type hints: `def foo(x: int) -> str:`
- Use `Optional[T]` for nullable values
- Use `Any` sparingly

### actionlint (GitHub Actions)

**Validates:**
- Workflow syntax
- Job dependencies
- Matrix configurations
- Expression syntax

**Common issues:**
- Undefined secrets: `${{ secrets.MISSING_SECRET }}`
- Invalid shell: `shell: bash` vs `shell: sh`
- Missing `if` conditions

---

## Workflow Integration

### Daily Development

```bash
# 1. Make changes
vim scripts/cli/jmo.py

# 2. Stage changes
git add scripts/cli/jmo.py

# 3. Commit (hooks run automatically)
git commit -m "feat: add new CLI flag"
# Output: ruff, black, mypy, bandit run automatically

# 4. Push (pre-push hooks run)
git push
# Output: Python import checks run automatically
```

### Skipping Hooks (Emergencies Only)

```bash
# Skip all hooks (NOT RECOMMENDED)
git commit --no-verify -m "emergency fix"

# Skip specific hook (v0.7.1+)
SKIP=deps-compile git commit -m "fix: typo in docs"

# Skip multiple hooks
SKIP=deps-compile,mypy git commit -m "WIP: draft changes"
```

**When to skip:**
- Emergency hotfixes (revert later)
- WIP commits (clean up before push)
- Dependency updates (when you know Python version is correct)

**Never skip:**
- Security hooks (detect-private-key, bandit)
- Dependency compilation (unless you manually verified Python 3.10+)

### Updating Hooks

```bash
# Update to latest hook versions
pre-commit autoupdate

# Review changes
git diff .pre-commit-config.yaml

# Test updated hooks
pre-commit run --all-files

# Commit
git add .pre-commit-config.yaml
git commit -m "deps(pre-commit): update hooks"
```

---

## Troubleshooting

### Error: "deps-compile requires Python 3.10+"

**Cause:** No Python 3.10+ interpreter found on system.

**Fix:**

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3.11

# macOS (Homebrew)
brew install python@3.11

# Verify installation
python3.11 --version
```

### Error: "hook id 'deps-compile' is unknown"

**Cause:** Pre-commit hooks not installed.

**Fix:**

```bash
make pre-commit-install
```

### Error: "pip-tools not installed"

**Cause:** `pip-tools` not available in active Python environment.

**Fix:**

```bash
# Install for Python 3.11
python3.11 -m pip install --user pip-tools

# Verify
python3.11 -m piptools --version
```

### Error: "Cannot install <package> because of conflicting dependencies"

**Cause:** Dependency conflicts in `requirements-dev.in`.

**Fix:**

1. Check conflicts:
   ```bash
   python3.11 scripts/dev/update_dependencies.py --validate
   ```

2. Review error messages for conflicting packages

3. Pin conflicting package in `requirements-dev.in`:
   ```bash
   # Example: checkov requires packaging<24.0
   echo "packaging<24.0  # Required by checkov" >> requirements-dev.in
   ```

4. Recompile:
   ```bash
   make deps-compile
   ```

### Hook takes too long

**Cause:** Large codebase or slow tools (mypy, bandit).

**Solutions:**

1. **Run hooks in parallel** (default in pre-commit):
   ```yaml
   # .pre-commit-config.yaml
   default_stages: [commit]
   fail_fast: false  # Continue even if one hook fails
   ```

2. **Skip slow hooks for WIP commits:**
   ```bash
   SKIP=mypy,bandit git commit -m "WIP: draft"
   # Run before push: pre-commit run --all-files
   ```

3. **Use pre-commit CI** (GitHub Actions):
   - Runs hooks in CI instead of locally
   - Faster local commits
   - See `.github/workflows/ci.yml`

---

## CI Integration

### Automated Hook Execution

The CI workflow (`.github/workflows/ci.yml`) runs hooks automatically:

```yaml
- name: Run pre-commit hooks
  run: pre-commit run --all-files
```

**Differences from local:**
- **All files checked** (not just staged files)
- **Fails CI if any hook fails**
- **Cached for speed** (pre-commit cache persisted)

### Skipped Hooks in CI

Some hooks are skipped in CI for performance:

```yaml
# .github/workflows/ci.yml
env:
  SKIP: deps-compile  # Handled separately in CI
```

**Rationale:** CI already validates `requirements-dev.txt` in a separate step with explicit Python version control.

---

## Best Practices

### ✅ DO

- ✅ **Install hooks immediately** after cloning repo
- ✅ **Run `make pre-commit-run` before pushing** to catch all issues
- ✅ **Update hooks monthly** with `pre-commit autoupdate`
- ✅ **Fix hook failures** instead of skipping
- ✅ **Use Python 3.10+ for development** to avoid auto-reexec overhead

### ❌ DON'T

- ❌ **Never skip security hooks** (detect-private-key, bandit)
- ❌ **Never commit with `--no-verify`** unless emergency
- ❌ **Never modify `.pre-commit-config.yaml` without testing**
- ❌ **Never pin hook versions** (use `autoupdate` instead)
- ❌ **Never compile requirements-dev.txt manually** (use hook or `make deps-compile`)

---

## Hook Customization

### Adding a New Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/example/my-hook
    rev: v1.0.0
    hooks:
      - id: my-hook-id
        name: My Custom Hook
        args: ["--flag", "value"]
        files: ^scripts/  # Only run on scripts/
```

### Disabling a Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/example/my-hook
    rev: v1.0.0
    hooks:
      - id: my-hook-id
        exclude: .*  # Never run this hook
```

### Running Hook on Specific Files

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/example/my-hook
    rev: v1.0.0
    hooks:
      - id: my-hook-id
        files: ^(scripts|tests)/.*\.py$  # Only Python files in scripts/ or tests/
```

---

## Performance Optimization

### Hook Execution Times (Typical)

| Hook | Files | Time | Parallel |
|------|-------|------|----------|
| trailing-whitespace | All | <1s | Yes |
| ruff | *.py | 2-5s | Yes |
| black | *.py | 3-8s | Yes |
| mypy | scripts/*.py | 10-30s | No |
| bandit | scripts/*.py | 5-15s | No |
| shellcheck | *.sh | 2-5s | Yes |
| actionlint | .github/workflows/*.yml | 3-8s | No |
| deps-compile | requirements-dev.in | 30-60s | N/A |

**Total (typical commit):** 30-60 seconds
**Total (deps update):** 60-90 seconds

### Speed Up Hooks

1. **Use `fail_fast: false`** (default):
   - Runs all hooks in parallel
   - Shows all failures at once

2. **Cache dependencies:**
   ```bash
   # pre-commit caches hook environments automatically
   # Clear cache to fix issues:
   pre-commit clean
   ```

3. **Skip slow hooks for WIP:**
   ```bash
   SKIP=mypy,bandit git commit -m "WIP"
   ```

4. **Use pre-commit.ci** (cloud-based):
   - Offloads hook execution to CI
   - Free for public repos
   - See https://pre-commit.ci/

---

## Lessons Learned (v0.7.1)

### What We Fixed

**Before v0.7.1:**
- `deps-compile` hook used active Python (often 3.8 in venvs)
- Caused dependency conflicts and downgrades
- Required manual `SKIP=deps-compile` or `python3.11 -m piptools compile`

**After v0.7.1:**
- Hook auto-detects and re-executes with Python 3.10+
- Prevents dependency mismatches automatically
- Zero manual intervention required

**Impact:**
- **Time saved:** 5-10 minutes per dependency update (no manual debugging)
- **Error prevention:** Catches Python version issues before commit
- **Developer experience:** Seamless workflow regardless of active Python

### Prevention Mechanisms

1. **Auto-reexec:** Script detects Python version and re-runs with correct version
2. **Clear errors:** If no Python 3.10+ found, provides installation instructions
3. **CI validation:** GitHub Actions validates Python version independently
4. **Documentation:** This guide prevents future confusion

---

## References

- **Pre-commit Documentation:** https://pre-commit.com/
- **Hook Configuration:** [.pre-commit-config.yaml](../.pre-commit-config.yaml)
- **Dependency Management:** [docs/DEPENDENCY_MANAGEMENT.md](DEPENDENCY_MANAGEMENT.md)
- **CI Workflow:** [.github/workflows/ci.yml](../.github/workflows/ci.yml)

---

**Last Updated:** 2025-10-23 (v0.7.1)
**Maintainer:** JMo Security Team
**Next Review:** 2025-11-23 (monthly)
