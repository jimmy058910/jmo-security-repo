---
name: jmo-ci-debugger
description: Diagnose and fix GitHub Actions CI failures using proven fixes from battle-tested patterns. Use when CI is failing, pre-commit hooks break, or release workflows error.
user-invocable: true
context: fork
allowed-tools: Read, Glob, Grep, Bash, WebFetch
---

## Live Context

**Recent CI runs:**
!gh run list --limit 5 --json status,conclusion,name 2>/dev/null || echo "gh CLI not available"

---

## Purpose

Diagnose and fix JMo Security GitHub Actions CI failures using proven fixes from documented "Lessons Learned." Every fix has been battle-tested in production CI/CD workflows.

**When to Use:**

- CI/CD workflows failing (ci.yml, release.yml)
- actionlint, yamllint, or Docker errors
- Pre-commit hooks failing in CI but passing locally
- Pull request checks blocked by CI failures
- Release workflows failing during Docker build/push

**Approach:** Diagnose before fixing. Identify root cause from logs before proposing changes.

## CI Workflow Architecture

### ci.yml (Primary CI Pipeline)

**Jobs:**

```yaml
jobs:
  quick-checks:      # 2-3 min
    - actionlint, yamllint, deps-compile freshness, security guardrails

  test-matrix:       # 10-15 min (parallel)
    - Ubuntu/macOS x Python 3.10/3.11/3.12
    - pytest with >=85% coverage threshold

  lint-full:         # 5-10 min (nightly only)
    - Complete pre-commit suite (all markdown, Python, shell, YAML)
```

**Triggers:** push to main/feature, pull_request to main, workflow_dispatch, schedule (nightly 6 AM UTC)

**Files:** [.github/workflows/ci.yml](../../.github/workflows/ci.yml)

### release.yml (Release Automation)

**Jobs:**

```yaml
jobs:
  pypi-publish:      # 3-5 min - Build wheel/sdist, publish via Trusted Publishers (OIDC)
  docker-build:      # 15-20 min - Multi-arch images (amd64, arm64), 3 variants
  docker-scan:       # 5-10 min - Trivy scanning, SARIF upload
  docker-hub-readme: # 1-2 min - Gated by DOCKERHUB_ENABLED variable
```

**Triggers:** push with version tags (`v*`), workflow_dispatch

**Files:** [.github/workflows/release.yml](../../.github/workflows/release.yml)

## Failure Catalog

| # | Failure | Key Symptom | Key Fix | Difficulty |
|---|---------|-------------|---------|------------|
| 1 | Docker Tag Extraction | `invalid reference format: v*` | Use `docker/metadata-action` (strips 'v' automatically) | Easy |
| 2 | Actionlint Parameters | `fail_on_error is not valid` | Use `fail_level: error` instead | Easy |
| 3 | Docker Testing Command | `unknown flag: --version` | Use `--help` (JMo has no `--version` flag) | Easy |
| 4 | SARIF Upload Permission | `Resource not accessible` | Add `security-events: write` permission | Easy |
| 5 | Docker Hub README Sync | `Authentication failed` / `401` | Use v4 action, PAT token, `DOCKERHUB_ENABLED` gate | Medium |
| 6 | Dependabot Cascading | `ModuleNotFoundError` (13+ PRs) | `@dependabot rebase` via `gh pr comment` | Easy |
| 7 | Markdownlint | `MD036/no-emphasis-as-heading` | Fix ALL violations: headings, blank lines, code fence langs | Easy |
| 8 | Pre-commit Hooks | `ruff...Failed` / `black...Failed` | Run `make fmt` then `pre-commit run --all-files` | Easy-Med |
| 9 | Test Coverage | `Coverage of X% below 85%` | Add missing tests for uncovered lines | Medium |
| 10 | Requirements Drift | `requirements-dev.txt mismatch` | Run `make deps-compile`, commit both files | Easy |
| 11 | YAML Syntax | `syntax error: expected <block` | Fix indentation, quote special chars, use 2-space indent | Easy-Med |
| 12 | Branch Protection | `GH013: Repository rule violations` | Use feature branches + PRs (never push directly to main) | Easy |
| 13 | Rulesets/Commit Status | `waiting for status to be reported` | Add `createCommitStatus` step with `actions/github-script` | Medium |
| 14 | Nightly Cascading | `lint-full: 4+ tool failures` | Fix in order: deps-compile, actionlint, mypy, markdownlint | Medium |
| 15 | Ruff After Black | `F401`/`F541` after formatting | Run `ruff check --fix` after Black, review auto-fixes | Easy |
| 16 | Platform Float Precision | `assert 0.X <= Y.YYY` across platforms | Find min/max across ALL platforms, add 5-20% buffer | Medium |
| 17 | React Build Check | `FileNotFoundError: React dashboard` | Add `SKIP_REACT_BUILD_CHECK` autouse fixture to test file | Easy |

See [complete failure catalog](references/ci-failure-catalog.md) for detailed symptoms, root causes, and proven fixes for each failure.

## CI Debugging Workflow

### 1. Identify Failing Job/Step

In GitHub Actions UI: click failed run, identify which job failed (quick-checks, test-matrix, docker-build), expand failed step, copy error message.

### 2. Match Error to Failure Pattern

Use the [error pattern matching reference](references/error-pattern-matching.md) or this quick lookup:

- `invalid reference format` -> #1 Docker Tags
- `fail_on_error is not valid` -> #2 Actionlint
- `unknown flag: --version` -> #3 Docker Testing
- `Resource not accessible` -> #4 SARIF Upload
- `Authentication failed` -> #5 Docker Hub
- `ModuleNotFoundError` (multiple PRs) -> #6 Dependabot
- `MD036/no-emphasis-as-heading` -> #7 Markdownlint
- `ruff...Failed` -> #8 Pre-commit / #15 Ruff After Black
- `Coverage of X% is below` -> #9 Test Coverage
- `requirements-dev.txt does not match` -> #10 Requirements Drift
- `syntax error: expected <block` -> #11 YAML Syntax
- `GH013: Repository rule violations` -> #12 Branch Protection
- `waiting for status to be reported` -> #13 Rulesets/Commit Status
- `lint-full: 4+ tool failures` -> #14 Nightly Cascading
- `F401 imported but unused` / `F541 f-string` -> #15 Ruff After Black
- `assert 0.X <= Y.YYY` (cross-platform) -> #16 Platform Float Precision
- `FileNotFoundError: React dashboard` -> #17 React Build Check

### 3. Apply Proven Fix

Follow the fix from the [failure catalog](references/ci-failure-catalog.md). Every fix has been tested in production.

### 4. Test Locally Before Pushing

```bash
make fmt && make lint && make test    # Pre-flight checklist
yamllint .github/workflows/*.yml      # YAML validation
actionlint .github/workflows/*.yml    # Actions validation
```

### 5. Push Fix and Monitor

```bash
git add <fixed_files>
git commit -m "fix(ci): <describe fix>"
git push
gh run watch  # Monitor CI run
```

### 6. Document New Failures

If you encounter a NEW failure pattern not in this skill, add it to the [failure catalog](references/ci-failure-catalog.md) and update the table above.

## Prevention Summary

Run before every push:

```bash
make pre-commit-install              # One-time setup
make fmt && make lint && make test   # Pre-push checks
```

Key prevention rules:

1. **Black before Ruff** - enforced in `.pre-commit-config.yaml` hook order
2. **Coverage >= 85%** - aim for 90%+ to maintain buffer
3. **Fix ALL violations** - not just new ones (Technical Debt Principle)
4. **Feature branches** - never push directly to main
5. **Cross-platform buffers** - 5-10% for floats, 20-30% for timing

See [full prevention strategies](references/prevention-strategies-full.md) for local CI simulation, enhanced pre-push hooks, and weekly maintenance routines.

## Quick Reference Commands

```bash
# Diagnose
gh run list --status=failure --limit 5     # Recent failures
gh run view <run-id> --log-failed          # Failed job logs
gh pr checks <pr-number> --watch           # PR check status

# Fix common issues
make fmt                                    # Auto-format (Black + Ruff)
make deps-compile                           # Recompile requirements lock
pre-commit run --all-files                  # Run all hooks
ruff check scripts/ tests/ --fix           # Auto-fix Ruff violations

# Validate before push
yamllint .github/workflows/*.yml           # YAML syntax
actionlint .github/workflows/*.yml         # Actions validation
pytest --cov --cov-report=term-missing     # Coverage report

# Monitor
gh run watch                               # Watch CI in real-time
gh run rerun <run-id> --failed             # Re-run failed jobs
```

## Additional References

- [Complete failure catalog](references/ci-failure-catalog.md) - All 17 failures with full detail
- [Error pattern matching](references/error-pattern-matching.md) - Regex patterns, diagnostic decision tree
- [Installation and configuration](references/installation-config.md) - Version pinning, Dockerfile patterns
- [Prevention strategies](references/prevention-strategies-full.md) - Pre-push hooks, local CI simulation
- [Memory integration](references/memory-integration.md) - `.jmo/memory/ci-fixes/` namespace, caching patterns

## Trigger Patterns

Use this skill when you see these phrases or questions:

- "CI is failing"
- "GitHub Actions workflow not working"
- "Docker build failed"
- "Tests passing locally but failing in CI"
- "CI timeout"
- "Workflow syntax error"
- "actionlint errors"
- "Why is the release workflow failing?"

## Notes

- **All fixes are proven:** Every fix has been tested in JMo Security's CI/CD
- **Test locally first:** Don't use CI as a testing ground
- **Fix root cause:** Don't just bypass checks
- **Document new patterns:** Add to failure catalog when you find new failures
- **Pre-commit is your friend:** Install hooks to catch issues before push
- **YAML is picky:** Use yamllint and actionlint religiously
- **Permissions matter:** `security-events: write` required for SARIF uploads
