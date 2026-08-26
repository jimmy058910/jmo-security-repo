# Pre-Commit Hooks Guide

## Overview

JMo Security uses [pre-commit](https://pre-commit.com/) to enforce code quality, security, and consistency before commits reach the repository.

**Key Feature:** The `uv-lock` hook fails the commit when `uv.lock` and `pyproject.toml` disagree, so a stale lockfile can never reach CI.

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

1. **detect-private-key** — Prevent committing private keys
2. **check-added-large-files** — Block files >10MB
3. **bandit** — Python security linter (scripts/ only, strict config)

#### Code Quality - Python

1. **ruff** — Fast Python linter (auto-fix enabled)
2. **black** — Python formatter (opinionated)
3. **mypy** — Type checker (scripts/ only)

#### Code Quality - Shell

1. **shellcheck** — Shell script linter
2. **shfmt** — Shell script formatter

#### Code Quality - YAML

1. **yamllint** — Strict YAML linting (schema-agnostic)

#### Code Quality - Markdown

1. **markdownlint** — Markdown linting (accessibility, rendering)

#### CI/CD Validation

1. **actionlint** — Validate GitHub Actions workflows

#### Dependency Management

1. **uv-lock** — Verify `uv.lock` matches `pyproject.toml`
2. **pip-audit** — Scan the locked dependency set for known CVEs (OSV database)

---

## Hook Details

### uv-lock (Critical)

**Purpose:** Ensures `uv.lock` stays consistent with the dependencies declared in `pyproject.toml`.

**Behavior:**

1. Triggers when `pyproject.toml` or `uv.lock` is modified
2. Installs the pinned `uv==0.11.15` if `uv` is not already available
3. Runs `uv lock --check`
4. Fails the commit if the lock is stale

**Example Output (stale lock):**

```bash
$ git commit -m "deps: add tabulate"
The lockfile at `uv.lock` needs to be updated, but `--check` was provided.
ERROR: uv.lock is out of date with pyproject.toml.
Run: make deps-lock
```

Fix with `make deps-lock && git add uv.lock`.

**Why This Matters:**

`uv.lock` is the single source of installed versions for local development and every CI job. A commit that changes `pyproject.toml` without regenerating the lock produces an environment nobody can reproduce, and CI's `uv sync --locked` hard-fails on it. Catching it at commit time keeps that feedback local.

**Why it is a local hook, not `astral-sh/uv-pre-commit`:** `maintenance.yml` runs `pre-commit autoupdate` weekly, which would drift a third-party hook's rev away from the uv version pinned at every other site — reintroducing the resolver divergence the uv.lock migration removed.

### bandit (Security)

**Configuration:** `pyproject.toml` under `[tool.bandit]`

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

**Strict mode:** Core modules have `disallow_untyped_defs = true`:

- `scripts.core.common_finding`
- `scripts.core.config`
- `scripts.core.plugin_api`
- `scripts.core.schema_validator`

**Common fixes:**

- Add type hints: `def foo(x: int) -> str:`
- Use `Optional[T]` for nullable values
- Use `Any` sparingly

**Type ignore requirements:**

- All `# type: ignore` must include error codes: `# type: ignore[attr-defined]`
- Add explanation comment: `# type: ignore[assignment]  # Reason here`

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

# Skip specific hook
SKIP=uv-lock git commit -m "fix: typo in docs"

# Skip multiple hooks
SKIP=uv-lock,mypy git commit -m "WIP: draft changes"
```

**When to skip:**

- Emergency hotfixes (revert later)
- WIP commits (clean up before push)

**Never skip:**

- Security hooks (detect-private-key, bandit)
- `uv-lock` on a commit that touches `pyproject.toml` — CI's `uv sync --locked` will fail anyway, just later and further from the change

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

### Error: "uv.lock is out of date with pyproject.toml"

**Cause:** Dependencies were changed in `pyproject.toml` without regenerating the lock.

**Fix:**

```bash
make deps-lock
git add uv.lock
```

### Error: "hook id 'uv-lock' is unknown"

**Cause:** Pre-commit hooks not installed.

**Fix:**

```bash
make pre-commit-install
```

### Error: "uv not installed"

**Cause:** `uv` not available on PATH. The hook installs it automatically, so this only appears if that install fails.

**Fix:**

```bash
python -m pip install uv==0.11.15   # pinned: matches every other site
uv --version
```

### A dependency resolves to an unexpected version

**Cause:** Declarations are floors (`>=`), so a fresh resolve floats to the newest compatible release.

**Fix:**

1. See what actually moved:

   ```bash
   git diff uv.lock
   ```

2. If a major bump is unwanted, add an upper bound in `pyproject.toml` with a comment saying why (see `mcp[cli]>=1.0.0,<2` for the pattern), then:

   ```bash
   make deps-lock
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

Some hooks are skipped for performance or because CI covers them separately:

```yaml
# .github/workflows/scheduled.yml -- Lint (full pre-commit suite)
env:
  SKIP: bandit,yamllint
```

`bandit` is already covered by `make lint`, and `yamllint` is skipped there only to avoid descending into third-party pre-commit cache fixtures.

**`uv-lock` is deliberately NOT skipped.** Its predecessor (`deps-compile`) had to be, because Dependabot's pip resolver left `requirements-dev.txt` in a non-canonical format after every bot merge, so `main` could not satisfy the check. Dependabot now regenerates `uv.lock` with uv, making the lock on `main` canonical by construction — the check is safe to run everywhere, and `ci.yml` runs `uv lock --check` on every event and author.

---

## Best Practices

### ✅ DO

- ✅ **Install hooks immediately** after cloning repo
- ✅ **Run `make pre-commit-run` before pushing** to catch all issues
- ✅ **Update hooks monthly** with `pre-commit autoupdate`
- ✅ **Fix hook failures** instead of skipping
- ✅ **Regenerate `uv.lock` in the same commit** as any `pyproject.toml` dependency change

### ❌ DON'T

- ❌ **Never skip security hooks** (detect-private-key, bandit)
- ❌ **Never commit with `--no-verify`** unless emergency
- ❌ **Never modify `.pre-commit-config.yaml` without testing**
- ❌ **Never pin hook versions** (use `autoupdate` instead)
- ❌ **Never hand-edit `uv.lock`** (use `make deps-lock`)

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
| uv-lock | pyproject.toml, uv.lock | 1-3s | N/A |
| pip-audit | pyproject.toml, uv.lock | 30-60s | N/A |

**Total (typical commit):** 30-60 seconds
**Total (deps update):** 90-120 seconds (includes pip-audit network call)

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
   - See <https://pre-commit.ci/>

---

## Lessons Learned

### One gate, everywhere, for everyone

`uv-lock` replaced a `deps-compile` gate that compared a freshly compiled
`requirements-dev.txt` byte-for-byte against the committed one. That gate could
never run unconditionally: Dependabot edited the generated file with its own pip
resolver, whose output differed structurally from uv's, so the check had to be
scoped to non-Dependabot pull requests. `main` then routinely held a format that
failed the next human PR.

The lesson is that **a gate you have to exempt writers from is not a gate.** The
fix was removing the second writer, not refining the exemption. `uv lock --check`
is resolver-symmetric, so bot and human commits face the identical check with no
event scoping and no SKIP list.

**Prevention mechanisms:**

1. **Commit-time check:** `uv-lock` fails locally before a stale lock reaches CI
2. **CI check:** `uv lock --check` runs on every event and author
3. **Same resolver everywhere:** Dependabot regenerates `uv.lock` with uv
4. **Drift guards:** `tests/unit/test_dep_audit_drift.py` and
   `tests/unit/test_uv_lock_platform_coverage.py`

---

## References

- **Pre-commit Documentation:** <https://pre-commit.com/>
- **Hook Configuration:** [.pre-commit-config.yaml](../../.pre-commit-config.yaml)
- **Dependency Management:** [DEPENDENCY_MANAGEMENT.md](DEPENDENCY_MANAGEMENT.md)
- **CI Workflow:** [.github/workflows/ci.yml](../../.github/workflows/ci.yml)

---

**Last Updated:** February 2026
**Maintainer:** JMo Security Team
