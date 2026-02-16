# Contributing to JMo Security

Thanks for your interest in contributing! This project started as a Cybersecurity Capstone and has grown into a general-purpose security audit toolkit. Contributions of all kinds are welcome—code, docs, tests, examples, and issue triage.

## Code of Conduct

Be respectful and constructive. We expect contributors to follow a standard code of conduct. If issues arise, contact the maintainer.

## How to get started

- Good first issues: <https://github.com/jimmy058910/jmo-security-repo/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22>
- Browse open issues: <https://github.com/jimmy058910/jmo-security-repo/issues>
- Ask questions by opening a discussion or issue.

## Development setup

- Python 3.10+ (CI validates on 3.10, 3.11, 3.12 across Ubuntu and macOS)
- **v1.0.0:** 2,981 tests, 87% coverage (CI requires ≥85%)
- Recommended commands:

```bash
pip install -e ".[dev]"                # Install in editable mode with dev deps
make pre-commit-install                # Setup pre-commit hooks
jmo tools install --profile balanced   # Install security tools (18 tools)
make test                              # Run unit tests and coverage
make fmt && make lint
```

### Unified Scan Profiles (v1.0.0)

CLI profiles and Docker variants are unified - same 4 profiles, same tools:

| Profile | Tools | Time | Use Case | Docker Tag |
|---------|-------|------|----------|------------|
| `fast` | 8 | 5-10 min | Pre-commit, PR validation | `jmo-security:fast` |
| `slim` | 14 | 12-18 min | Cloud/IaC (AWS/Azure/GCP/K8s) | `jmo-security:slim` |
| `balanced` | 18 | 18-25 min | Production scans, CI/CD | `jmo-security:balanced` |
| `deep` | 28 | 40-70 min | Compliance audits, pentests | `jmo-security:deep` |

**Canonical tool reference:** [docs/PROFILES_AND_TOOLS.md](docs/PROFILES_AND_TOOLS.md)

## Dependency management

This repo keeps Python runtime deps minimal (declared in `pyproject.toml`; optional extras under `[project.optional-dependencies]`) and relies on a few external security tools installed on your system. Here's the recommended way to install and update everything.

### Packaging Note (PEP 621)

This project uses modern **PEP 621** packaging via `pyproject.toml`. Legacy `setup.py`/`setup.cfg` fields like `long_description_content_type` are not needed—setuptools 61.0+ automatically detects `README.md` as Markdown. When contributing, all metadata changes should be made in `pyproject.toml` under the `[project]` section.

### Python environment

- Create and use a local virtualenv (the Makefile auto-detects `.venv`):

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip setuptools wheel
```

- Install dev dependencies and the package in editable mode:

```bash
make dev-setup
# Optional reporters and YAML: install extras
pip install -e ".[reporting]"
```

- Update Python tooling/deps:

```bash
python -m pip install -U pip setuptools wheel
make dev-deps   # re-installs latest unpinned dev deps from requirements-dev.txt
```

Notes:

- `requirements-dev.txt` is intentionally lightweight. For reproducible, pinned dev deps, this repo now includes a `requirements-dev.in` and Make targets for pip-tools and uv.

### Reproducible dev deps (pip-tools or uv)

Use pip-tools (default):

```bash
make upgrade-pip         # optional but recommended
make deps-compile        # compile requirements-dev.in -> requirements-dev.txt
make deps-sync           # sync your env to requirements-dev.txt (installs/removes as needed)
```

Or use uv (fast alternative) if installed:

```bash
make uv-sync
```

CI note: Pull requests include an automated check that `requirements-dev.txt` matches `requirements-dev.in`. If it fails, run `make deps-compile` locally, commit the updated `requirements-dev.txt`, and push.

### External security tools (CLI)

Use the built-in tool manager to install security tools (cross-platform):

```bash
# Check which tools are installed for your profile
jmo tools check --profile balanced

# Install missing tools (auto-detects platform)
jmo tools install --profile balanced

# Update outdated tools
jmo tools update

# Update only critical security tools
jmo tools update --critical-only

# Show outdated tools
jmo tools outdated

# Update a specific tool
jmo tools update --tool trivy

# Uninstall JMo and all tools
jmo tools uninstall --all
```

### Version Management (v1.0.0 - CRITICAL)

Tool versions are centrally managed via `versions.yaml`. **NEVER manually edit tool versions in Dockerfiles!**

```bash
# Check for available updates
python3 scripts/dev/update_versions.py --check-latest

# Update specific tool in versions.yaml
python3 scripts/dev/update_versions.py --tool trivy --version 0.68.0

# Sync Dockerfiles with versions.yaml
python3 scripts/dev/update_versions.py --sync

# View current version report
python3 scripts/dev/update_versions.py --report
```

**Critical tools** (must be updated within 7 days of new release): trivy, trufflehog, semgrep, checkov, zap, syft, prowler, kubescape

**Complete guide:** [docs/VERSION_MANAGEMENT.md](docs/VERSION_MANAGEMENT.md)

### Pre-commit hooks

- Install and enable hooks:

```bash
make pre-commit-install
```

- Update all hook versions to the latest:

```bash
pre-commit autoupdate
```

### When to bump project dependencies

- Runtime deps live in `pyproject.toml`. If you need newer features or fixes from `PyYAML`/`jsonschema` (used for reporting), bump the constraints under `[project.optional-dependencies]` and open a PR with a brief note in `CHANGELOG.md`.
- Dev-only tools are managed via `requirements-dev.txt` and pre-commit; prefer updating them via `pre-commit autoupdate` and re-running `make dev-deps`.

If you’re unsure which path to use, open an issue and we’ll help you choose between bumping project deps vs. updating local dev tooling.

## Pre-commit Hooks

We use [pre-commit](https://pre-commit.com/) to automatically run formatting and linting checks before each commit. This ensures code quality and consistency.

### Installation

Install pre-commit using pip or pipx:

```bash
# Using pip
pip install pre-commit

# OR using pipx (isolated environment)
pipx install pre-commit
```

Alternatively, use the project's Makefile:

```bash
make pre-commit-install
```

### Enable hooks

After installing pre-commit, enable it in your local repository:

```bash
pre-commit install
```

This will configure git to run the hooks automatically before each commit.

### Manual execution

To run pre-commit checks on all files manually:

```bash
pre-commit run --all-files
```

Or use the Makefile shortcut:

```bash
make pre-commit-run
```

### What's included

The repository includes a `.pre-commit-config.yaml` file that configures the following checks:

- **pre-commit-hooks**: housekeeping checks
  - trailing-whitespace, end-of-file-fixer, mixed-line-ending
  - check-yaml, check-json, check-toml
  - detect-private-key
  - check-added-large-files (10 MB limit)
- **Ruff**: Python linting and formatting
- **Black**: Python code formatting
- **shfmt**: Shell script formatting
- **shellcheck**: Shell script static analysis
- **yamllint**: YAML linting
- **actionlint**: GitHub Actions workflow validation
- **markdownlint**: Markdown style checks
- **Bandit**: Python security scanning (scoped to `scripts/`; this hook is skipped in CI but covered by `make lint` locally)

These checks run automatically on commit and are also enforced in CI (note: the Bandit hook is skipped in CI's pre-commit stage; see `.github/workflows/ci.yml`).

#### Tips

- If you see "pre-commit: command not found", run `make dev-deps` (installs Python dev deps including pre-commit), or install via pip/pipx as above.
- Update hooks to the latest versions from `.pre-commit-config.yaml`:

  ```bash
  pre-commit autoupdate
  ```

- Run a single hook across the repo (example for Ruff):

  ```bash
  pre-commit run ruff --all-files
  ```

## Running the tool locally

### Basic workflow (v1.0.0)

```bash
# Quick scan with fast profile (8 tools, 5-10 min)
jmo scan --repo . --profile fast --human-logs

# Production scan with balanced profile (18 tools, 18-25 min)
jmo scan --repo . --profile balanced --human-logs

# Generate reports from existing scan
jmo report ./results --profile --human-logs

# CI mode with severity threshold
jmo ci --fail-on HIGH --profile balanced

# Compare scans (diff feature)
jmo diff results-baseline/ results-current/ --format md

# View scan history
jmo history list

# Trend analysis
jmo trends analyze --days 30
```

### Demo workflow (no external scanners required)

```bash
make screenshots-demo
```

### v1.0.0 Key Features

- **SQLite historical storage:** Trend analysis with `jmo history` and `jmo trends`
- **Machine-readable diffs:** CI/CD integration with `jmo diff`
- **Cross-tool deduplication:** 30-40% noise reduction via similarity clustering
- **6 compliance frameworks:** OWASP, CWE, CIS, NIST, PCI DSS, MITRE mappings

## Sample Fixtures and Output Regeneration

The repository includes sample fixtures for testing, documentation examples, and screenshot generation. These demonstrate JMo Security's v1.0.0 output format with the standardized metadata wrapper.

### Fixture Structure

The primary fixture is `samples/fixtures/infra-demo/`:

```text
samples/fixtures/infra-demo/
├── main.tf           # Terraform - IaC security scanning
├── deployment.yaml   # Kubernetes - container orchestration security
├── Dockerfile        # Docker - container security
├── secrets.json      # Secrets - secret detection testing
└── sample-results/   # Generated outputs (gitignored)
    └── summaries/
        ├── findings.json       # Machine-readable (v1.0.0 format)
        ├── findings.sarif      # GitHub/GitLab code scanning
        ├── findings.csv        # Spreadsheet export
        ├── SUMMARY.md          # PR comments
        ├── dashboard.html      # Interactive browser viewing
        └── simple-report.html  # Email-compatible report
```

This fixture is intentionally vulnerable, containing:

- **32 exposed secrets** (API keys, tokens in secrets.json)
- **6 IaC misconfigurations** (unrestricted security groups in main.tf)
- **4 container issues** (missing USER, unpinned packages in Dockerfile)
- **3 Kubernetes security issues** (runAsNonRoot, allowPrivilegeEscalation)

### v1.0.0 Output Format

All outputs use the standardized metadata wrapper:

```json
{
  "meta": {
    "output_version": "1.0.0",
    "jmo_version": "1.0.0",
    "schema_version": "1.2.0",
    "timestamp": "2025-12-22T10:30:00Z",
    "scan_id": "abc123",
    "profile": "balanced",
    "tools": ["trivy", "semgrep", "checkov", "..."],
    "finding_count": 68
  },
  "findings": [...]
}
```

### Regenerating Sample Outputs

Use these Makefile targets to regenerate sample outputs:

```bash
# Full regeneration (recommended)
make regenerate-samples

# Individual steps (if needed)
make samples-clean     # Remove old outputs
make samples-scan      # Run balanced profile scan (5-15 min)
make samples-report    # Generate all report formats
make samples-verify    # Verify v1.0.0 format compliance
```

### When to Regenerate Samples

Regenerate sample outputs when:

1. **Updating output formats** - Changes to reporters or schema
2. **Before releases** - Ensure SAMPLE_OUTPUTS.md examples match actual output
3. **After major adapter changes** - New tools or parsing changes
4. **Updating documentation screenshots** - Use `make screenshots-demo` after regeneration

### Time Estimates

| Target | Time | Notes |
|--------|------|-------|
| `samples-scan` | 5-15 min | Depends on installed tools |
| `samples-report` | ~30 sec | Quick report generation |
| `regenerate-samples` | 5-20 min | Full workflow |
| `screenshots-demo` | 5-20 min | Includes scan + screenshot |

### Verifying Output Format

The `samples-verify` target checks:

- All 6 output files exist (JSON, SARIF, CSV, MD, HTML×2)
- `findings.json` has valid v1.0.0 metadata wrapper
- Metadata includes required fields: `output_version`, `schema_version`, `finding_count`

```bash
make samples-verify
# Output:
# Checking required output files:
#   ✅ findings.json
#   ✅ SUMMARY.md
#   ✅ dashboard.html
#   ...
# Validating v1.0.0 metadata format:
#   ✅ output_version: 1.0.0
#   ✅ schema_version: 1.2.0
#   ✅ finding_count: 68
```

### Related Documentation

- [samples/README.md](samples/README.md) - Complete fixture documentation
- [SAMPLE_OUTPUTS.md](SAMPLE_OUTPUTS.md) - Example outputs reference
- [docs/RESULTS_GUIDE.md](docs/RESULTS_GUIDE.md) - Output format specification

## Docker local testing

Before publishing Docker images to GHCR, test them locally to validate changes.

### Docker Variants (v1.0.0)

Docker tags now match CLI profiles:

| Tag | Profile | Tools | Dockerfile |
|-----|---------|-------|------------|
| `fast` | fast | 8 | `Dockerfile.fast` |
| `slim` | slim | 14 | `Dockerfile.slim` |
| `balanced` | balanced | 18 | `Dockerfile.balanced` |
| `deep` / `latest` | deep | 28* | `Dockerfile` |

*3 deep profile tools require manual installation (AFL++, MobSF, Akto)

### Build local images

```bash
# Build all variants (fast/slim/balanced/deep)
make docker-build-local

# Or build specific variant
docker build -t jmo-security:local-balanced -f Dockerfile.balanced .
docker build -t jmo-security:local-fast -f Dockerfile.fast .
```

### Test local images

```bash
# Test CLI works
docker run --rm jmo-security:local-balanced --help
docker run --rm jmo-security:local-balanced ci --help

# Test scan with volume mount (CRITICAL: mount .jmo for history persistence)
docker run --rm \
  -v $(pwd):/scan \
  -v $(pwd)/.jmo:/scan/.jmo \
  -v $(pwd)/results:/results \
  jmo-security:local-balanced ci \
  --repo /scan \
  --results-dir /results \
  --profile balanced \
  --allow-missing-tools
```

**Important:** Mount `.jmo/history.db` for SQLite historical storage persistence.

### Run E2E tests with local images

```bash
# Set environment variables to use local images
export DOCKER_IMAGE_BASE="jmo-security"
export DOCKER_TAG="local-balanced"

# Run specific Docker tests
bash tests/e2e/run_comprehensive_tests.sh --test U9
bash tests/e2e/run_comprehensive_tests.sh --test U10
bash tests/e2e/run_comprehensive_tests.sh --test U11

# Or run full suite
bash tests/e2e/run_comprehensive_tests.sh
```

### Pre-release Docker checklist

Before pushing Docker images:

- [ ] Build all four variants locally (fast/slim/balanced/deep)
- [ ] Test CLI works (`--help`, `scan --help`, `ci --help`)
- [ ] Test single repo scan with each profile
- [ ] Test multi-target scan (repo + image + IaC)
- [ ] Verify `.jmo/history.db` persistence with volume mount
- [ ] Run E2E tests U9, U10, U11 with local images
- [ ] Verify image sizes are reasonable

## Package Manager Testing

Before submitting Homebrew/WinGet PRs, test the packages locally.

### Test Homebrew Formula

```bash
# Install from local formula
brew install --build-from-source packaging/homebrew/jmo-security.rb

# Verify installation
jmo --help
jmo scan --help
jmo tools --help
jmo wizard --help

# Run formula tests
brew test jmo-security

# Audit formula (checks best practices)
brew audit --strict --online jmo-security

# Test upgrade path (if updating existing formula)
brew upgrade jmo-security

# Cleanup
brew uninstall jmo-security
```

**Note:** `jmotools` was consolidated into `jmo` in v0.9.0. All commands now use the `jmo` CLI.

### Test WinGet Package (Windows)

```powershell
# Build installer
python packaging/windows/build_installer.py --version 0.9.0

# Validate manifest
wingetcreate validate packaging/winget/manifests/j/jmo/jmo-security/0.9.0

# Install from local manifest
winget install --manifest packaging/winget/manifests/j/jmo/jmo-security/0.9.0

# Verify installation
jmo --help
jmo scan --help

# Test upgrade path
winget upgrade jmo.jmo-security

# Cleanup
winget uninstall jmo.jmo-security
```

### Pre-release Package Manager Checklist

Before submitting to Homebrew/WinGet:

- [ ] Test local formula/manifest installation
- [ ] Verify CLI works (`jmo --help`, `jmo scan --help`, `jmo tools --help`)
- [ ] Test upgrade path from previous version
- [ ] Run `brew audit` (macOS) or `wingetcreate validate` (Windows)
- [ ] Verify all dependencies bundled correctly
- [ ] Test on fresh system (VM or Docker container)
- [ ] Check package size is reasonable

**Complete packaging guide:** [packaging/README.md](packaging/README.md) | [packaging/TESTING.md](packaging/TESTING.md)

## Git Workflow

**Branching Strategy:** Git Flow with `dev` + feature branches

### Branch Structure

```text
main ← stable releases only (tagged versions)
  └── dev ← active development
        ├── feature/ai-remediation
        ├── feature/diff-reports
        └── ... (other features)
```

**Branch Purposes:**

- **`main`** — Stable releases only, tagged with version numbers
- **`dev`** — Active development, integration point for all features
- **`feature/*`** — Individual features, one per major change
- **`hotfix/*`** — Critical bug fixes for released versions

### Starting a New Feature

```bash
# Always start from latest dev
git checkout dev
git pull origin dev
git checkout -b feature/my-feature dev

# Example: Add new security tool adapter
git checkout -b feature/add-snyk-adapter dev
```

### Daily Work Cycle

```bash
# Make changes
vim scripts/core/adapters/snyk_adapter.py

# Stage and commit with conventional commit format
git add scripts/core/adapters/snyk_adapter.py
git commit -m "feat(tools): add Snyk adapter"

# Push to GitHub (backs up your work)
git push origin feature/add-snyk-adapter
```

### Conventional Commit Prefixes

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Test additions/changes
- `refactor:` Code refactoring
- `perf:` Performance improvements
- `chore:` Maintenance tasks

### Working on Multiple Features

```bash
# Start Feature #1
git checkout -b feature/tools-1.0.0 dev
# ... work ...
git commit -m "feat: add tools"

# Switch to Feature #2 (pause #1)
git checkout dev
git checkout -b feature/ai-remediation dev
# ... work ...
git commit -m "feat: add AI MCP"

# Return to Feature #1
git checkout feature/tools-1.0.0
# ... continue work ...
```

### Merging Feature to Dev

```bash
# When feature is complete
pytest tests/adapters/test_snyk_adapter.py -v
make lint
make test

# Switch to dev and merge
git checkout dev
git pull origin dev
git merge feature/add-snyk-adapter

# Push merged dev
git push origin dev

# Optional: Delete feature branch
git branch -d feature/add-snyk-adapter
```

### Release Process

```bash
# After all features complete on dev
git checkout main
git pull origin main
git merge dev

# Tag release
git tag vX.Y.Z

# Push to trigger CI/CD
git push origin main --tags

# CI automatically publishes to PyPI + Docker Hub
```

### Hotfix for Released Version

```bash
# Create hotfix from main
git checkout main
git checkout -b hotfix/vX.Y.Z

# Fix bug
vim scripts/cli/schedule_commands.py
git add . && git commit -m "fix(schedule): handle missing directory"

# Test thoroughly
make test

# Merge to main and tag
git checkout main
git merge hotfix/vX.Y.Z
git tag vX.Y.Z
git push origin main --tags

# Merge back to dev
git checkout dev
git merge hotfix/vX.Y.Z
git push origin dev
```

### Status Checks

```bash
# Where am I?
git branch --show-current

# What changed?
git status --short

# Recent commits
git log --oneline -5

# All feature branches
git branch -a | grep feature/

# What's merged to dev?
git log dev --oneline --graph
```

### Troubleshooting Git

**Merge Conflicts:**

```bash
# During merge, conflicts appear
git merge feature/your-feature

# Manually resolve conflicts
vim conflicted-file.py  # Fix <<< === >>> markers

# Stage resolved files
git add conflicted-file.py

# Complete merge
git commit -m "merge: resolve conflicts"
```

**Feature Branch Behind Dev:**

```bash
# Update feature branch with latest dev
git checkout feature/your-feature
git merge dev

# Or rebase (cleaner history, but rewrites commits)
git rebase dev
```

**Stash Changes Temporarily:**

```bash
# Save work without committing
git stash

# Switch branches
git checkout other-branch

# Return and restore work
git checkout original-branch
git stash pop
```

**Undo/Fix Commands:**

```bash
# Uncommit last commit (keep changes)
git reset --soft HEAD~1

# Discard all local changes (DANGER)
git reset --hard HEAD

# Revert a merge
git revert -m 1 HEAD
```

### Best Practices

- Create feature branches from `dev`, not `main`
- Keep diffs small and focused
- Write/update tests when changing behavior
- Run `make fmt && make lint && make test` before pushing
- Run `make pre-commit-run` to apply YAML linting and validate GitHub Actions workflows via actionlint
- Open a PR and fill out the template (if present). Link related issues
  - CI runs on a matrix (OS/Python). Workflows use concurrency to cancel redundant runs and set 20-minute timeouts per job

### Commit guidelines and pre-push validation

**CRITICAL:** Before pushing to `main`, ensure all new Python modules are tracked in git. Untracked modules cause Dependabot PRs to fail with `ModuleNotFoundError`.

#### Pre-push hook (automatic validation)

A pre-push git hook is installed in `.git/hooks/pre-push` that automatically checks for:

1. **Untracked Python files** in `scripts/` directory
2. **Missing critical modules** (compliance_frameworks, exceptions, tool_runner, etc.)
3. **Out-of-sync requirements files** (requirements-dev.in vs requirements-dev.txt)

The hook runs automatically before every push and takes ~5 seconds. To bypass in emergencies:

```bash
git push --no-verify  # Use sparingly - skips validation
```

#### Manual validation (before committing)

If you're adding new Python modules, verify they're tracked:

```bash
# Check for untracked files in scripts/
git status scripts/

# Add all new modules
git add scripts/

# Verify imports work
python3 -c "import scripts.core.your_new_module"
```

#### Why this matters

**Scenario:** You create `scripts/core/new_feature.py` but forget to `git add` it. You commit and push to `main`. Later, Dependabot creates 13 PRs to update dependencies. **All 13 PRs fail** because they're based on `main`, which is missing `new_feature.py`.

**Solution:** The pre-push hook catches this before it breaks Dependabot, preventing cascading failures.

#### Requirements file synchronization

When modifying `requirements-dev.in`:

```bash
# After editing requirements-dev.in
make deps-compile  # Regenerate requirements-dev.txt
git add requirements-dev.in requirements-dev.txt
git commit -m "deps: update development dependencies"
```

**CI validation:** Pull requests automatically check that `requirements-dev.txt` matches `requirements-dev.in`. If the check fails, run `make deps-compile` and commit the updated file.

## Weekly Maintenance Routine

To prevent technical debt accumulation and nightly CI failures, maintainers should follow this weekly maintenance routine:

### Monday Morning (After Nightly CI Run)

**Time: 15-30 minutes**

1. **Check nightly CI results:**

   ```bash
   gh run list --workflow=ci.yml --limit 5
   # Look for "CI" runs triggered by "schedule" at 6 AM UTC
   ```

2. **If nightly lint-full failed, investigate immediately:**

   ```bash
   # Get the failed run ID
   gh run view <run-id> --log-failed

   # Categorize failures (actionlint, markdownlint, mypy, deps-compile)
   # Follow jmo-ci-debugger skill pattern #14
   ```

3. **Apply Technical Debt Principle:**
   - Fix ALL violations found, not just new ones
   - Example: If markdownlint shows 8 issues, fix all 8 (not just your 3)
   - Rationale: Prevents compound debt, maintains codebase health

4. **Verify fixes locally before pushing:**

   ```bash
   # Run the same checks that failed in CI
   pre-commit run --all-files
   mypy scripts/
   npx markdownlint-cli2 "**/*.md" "#node_modules"
   ```

### Why This Matters

**Nightly CI catches issues that PR checks miss:**

- **PR checks (quick-checks):** Fast validation (2-3 min), runs actionlint, yamllint, deps-compile freshness
- **Nightly lint-full:** Comprehensive validation (8-12 min), runs full pre-commit suite including markdownlint, mypy, ruff, bandit

**Common cascade pattern:**

```text
Monday: Small markdownlint issue introduced (PR passes quick-checks)
Tuesday: Mypy type:ignore added (PR passes, lint-full not checked)
Wednesday: Another markdown issue (PR passes, debt accumulates)
Thursday: Nightly CI fails with 13 violations across 4 tools
```

**Prevention strategy:**

1. **Enhanced pre-push hook** (blocks bad commits locally)
2. **Lint Preview in CI** (catches 80% of issues in PRs)
3. **Weekly Monday check** (fixes anything that slipped through)
4. **jmo-ci-debugger skill** (documents proven fix patterns)

### Quick Commands

```bash
# Check last 5 CI runs
gh run list --workflow=ci.yml --limit 5

# View failed run logs
gh run view <run-id> --log-failed

# Run full local lint suite (matches nightly)
pre-commit run --all-files

# Fix all markdownlint issues
npx markdownlint-cli2 --fix "**/*.md" "#node_modules"

# Check mypy
mypy scripts/

# Rerun failed CI job
gh run rerun <run-id> --failed
```

## CI Troubleshooting

Detailed guide for diagnosing and fixing common CI failures on PRs to this repository.

### Quick Diagnosis

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

### Common Failure Patterns

#### 1. Markdownlint Failures

**Symptoms:**

```text
markdownlint.............................................................Failed
MD032/blanks-around-lists Lists should be surrounded by blank lines
MD040/fenced-code-language Fenced code blocks should have a language specified
```

**Quick Fix:**

1. **Blank lines around lists (MD032):** Add blank line BEFORE and AFTER lists
2. **Code fence language (MD040):** Change `` ``` `` to `` ```bash `` or `` ```text ``
3. **Emphasis as heading (MD036):** Change `**Bold**` to `## Heading`

```bash
# Run before committing documentation
pre-commit run markdownlint --all-files

# Or auto-fix
npx markdownlint-cli2 --fix "**/*.md" "#node_modules"
```

#### 2. Requirements Drift (deps-compile freshness)

**Symptoms:**

```text
requirements-dev.txt is out of date. Run: make deps-compile
```

**Root Cause:** Local `pip-compile` uses absolute paths, CI uses relative paths.

**Quick Fix:**

```bash
# Regenerate with relative paths
make deps-compile

# Verify no absolute paths
grep "/home/" requirements-dev.txt && echo "❌ Absolute paths detected!"
```

#### 3. Pre-commit Hook Version Drift

**Symptoms:**

```text
ruff....................................Failed
shellcheck..............................Failed
```

**Quick Fix:**

```bash
# Clean and reinstall hooks
pre-commit clean
pre-commit install --install-hooks
pre-commit run --all-files
```

#### 4. Test Coverage Below Threshold

**Symptoms:**

```text
FAILED: Coverage of 82% is below threshold of 85%
```

**Quick Fix:**

```bash
# Check coverage locally
pytest --cov --cov-report=term-missing

# View detailed HTML report
pytest --cov --cov-report=html
open htmlcov/index.html
```

#### 5. Actionlint Failures

**Symptoms:**

```text
.github/workflows/ci.yml:45:7: unexpected input 'fail_on_error'
```

**Quick Fix:**

```bash
# Validate workflows before committing
actionlint .github/workflows/*.yml

# Or via pre-commit
pre-commit run actionlint --files .github/workflows/ci.yml
```

### CI Environment Differences

| Aspect | Local | CI (GitHub Actions) |
|--------|-------|---------------------|
| **Python paths** | `/home/user/...` | Relative paths only |
| **pip-compile** | May use absolute paths | Always uses relative |
| **pre-commit cache** | `~/.cache/pre-commit` | Fresh on every run |
| **Tools** | May have extras | Minimal environment |

### Emergency Fixes

When CI is broken and you need to merge urgently:

**Option 1: Skip pre-commit (LAST RESORT)**

```bash
git push --no-verify  # ⚠️ Only for hotfixes!
```

**Option 2: Disable failing hook temporarily**

```yaml
# .pre-commit-config.yaml
  - id: markdownlint
    exclude: ^docs/problematic-file\.md$  # Skip specific file
```

**Option 3: Create bypass PR**

```bash
git checkout -b hotfix/bypass-ci
git commit --allow-empty -m "chore: bypass CI for hotfix"
gh pr create --title "Hotfix: bypass CI" --label "hotfix"
# Merge immediately, fix CI in follow-up PR
```

## Coding standards

- Python: Ruff for linting (`ruff check`) and `ruff format`/`black` for formatting.
- Shell: `shellcheck` and `shfmt -i 2 -ci -bn`.
- YAML: `yamllint` via pre-commit; GitHub Actions validated by `actionlint` (also enforced in CI).
- Keep public CLI flags and outputs stable; update docs/tests when behavior changes.

## Adding Tool Adapters (Plugin System)

JMo Security uses a plugin-based architecture for all 28 security tool adapters. This enables hot-reload during development, independent updates, and community-contributed integrations.

### Plugin Architecture Overview

**Key Benefits:**

- **Hot-Reload** - Edit adapter code without reinstalling JMo
- **Fast Development** - 4 hours → 1 hour per adapter (75% reduction)
- **Independent Updates** - Ship adapter improvements without core releases
- **Low-Risk Testing** - Test new tools in `~/.jmo/adapters/` without modifying core
- **Performance** - <100ms plugin loading overhead for all 28 adapters

**Core Components:**

| Component | File | Purpose |
|-----------|------|---------|
| Plugin API | `scripts/core/plugin_api.py` | Base classes, decorators, Finding dataclass |
| Plugin Loader | `scripts/core/plugin_loader.py` | Auto-discovery, registry, hot-reload |
| Integration | `scripts/core/normalize_and_report.py` | Dynamic adapter loading |

### Creating a New Adapter

**Plugin Search Paths (priority order):**

1. `~/.jmo/adapters/` - User plugins (highest priority, for testing)
2. `scripts/core/adapters/` - Built-in plugins (official adapters)

**Step 1: Create Adapter File**

> **Important:** Use the utilities in `scripts/core/adapters/common.py` for consistent JSON loading and error handling. This ensures proper UTF-8 handling, empty file detection, and standardized logging.
>
> **Severity Mapping:** Use `map_tool_severity()` from `scripts/core/common_finding.py` for tool-specific severity normalization. This centralized function handles mappings for ZAP, Semgrep, Nuclei, Falco, and falls back to generic normalization for other tools. See [Severity Mapping](#severity-mapping) for details.
>
> **Compliance Enrichment:** Adapters should NOT handle compliance enrichment. Return raw findings and let the report phase handle enrichment. All findings are enriched centrally in `normalize_and_report.py` via `enrich_findings_with_compliance()` after collection and deduplication. This single-pass batch operation is more efficient than per-adapter enrichment.

```python
# scripts/core/adapters/snyk_adapter.py
from pathlib import Path
from typing import List
from scripts.core.plugin_api import AdapterPlugin, Finding, PluginMetadata, adapter_plugin
from scripts.core.adapters.common import safe_load_json_file
from scripts.core.common_finding import map_tool_severity  # For tool-specific severity mapping

@adapter_plugin(PluginMetadata(
    name="snyk",  # CRITICAL: Must use underscores, matching adapter filename (snyk_adapter.py → "snyk")
    version="1.0.0",
    author="Your Name",
    description="Adapter for Snyk SCA scanner",
    tool_name="snyk",  # The actual binary/command name (can use hyphens like "dependency-check")
    schema_version="1.2.0",
    output_format="json",
    exit_codes={0: "clean", 1: "findings", 2: "error"}
))
class SnykAdapter(AdapterPlugin):
    @property
    def metadata(self):
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path) -> List[Finding]:
        """Parse Snyk JSON output and return CommonFinding objects"""
        # Use safe_load_json_file for consistent error handling
        data = safe_load_json_file(output_path, default={})
        if not data:
            return []

        findings = []

        for vuln in data.get("vulnerabilities", []):
            finding = Finding(
                schemaVersion="1.2.0",
                id="",  # Will be auto-generated
                ruleId=vuln["id"],
                severity=vuln["severity"].upper(),
                tool={
                    "name": "snyk",
                    "version": data.get("version", "unknown")
                },
                location={
                    "path": vuln.get("from", ["unknown"])[0],
                    "startLine": 1
                },
                message=vuln["title"],
                description=vuln.get("description", ""),
                remediation=vuln.get("fixedIn", "No fix available"),
                references=[{"url": vuln.get("url", "")}],
                raw=vuln  # Original payload for debugging
            )
            findings.append(finding)

        return findings
```

**Step 2: Add Adapter Tests**

```python
# tests/adapters/test_snyk_adapter.py
import pytest
import json
import tempfile
from pathlib import Path
from scripts.core.adapters.snyk_adapter import SnykAdapter

class TestSnykAdapter:
    @pytest.fixture
    def sample_output(self):
        """Sample Snyk JSON output"""
        return {
            "vulnerabilities": [
                {
                    "id": "SNYK-JS-LODASH-1234",
                    "title": "Prototype Pollution",
                    "severity": "high",
                    "from": ["lodash@4.17.19"],
                    "description": "Prototype pollution vulnerability",
                    "fixedIn": ["4.17.21"],
                    "url": "https://snyk.io/vuln/SNYK-JS-LODASH-1234"
                }
            ],
            "version": "1.0.0"
        }

    def test_parse_findings(self, sample_output):
        adapter = SnykAdapter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(sample_output, f)
            temp_path = Path(f.name)

        findings = adapter.parse(temp_path)
        assert len(findings) == 1
        assert findings[0].ruleId == "SNYK-JS-LODASH-1234"
        assert findings[0].severity == "HIGH"

        temp_path.unlink()

    def test_parse_empty(self):
        adapter = SnykAdapter()
        findings = adapter.parse(Path("/nonexistent/path.json"))
        assert findings == []

    def test_metadata(self):
        adapter = SnykAdapter()
        assert adapter.metadata.name == "snyk"
        assert adapter.metadata.schema_version == "1.2.0"
```

**Step 3: Validate and Test**

```bash
# Validate adapter structure
jmo adapters validate scripts/core/adapters/snyk_adapter.py

# Run adapter tests
pytest tests/adapters/test_snyk_adapter.py -v

# Integration test with real scan
jmo scan --repo ./myapp --tools snyk --results-dir results
jmo report results --human-logs
```

### CLI Commands for Adapters

```bash
# List all loaded plugins
jmo adapters list

# Validate custom adapter
jmo adapters validate ~/.jmo/adapters/custom_tool_adapter.py

# Output:
# ✅ Valid plugin: /home/user/.jmo/adapters/custom_tool_adapter.py
#   Plugin: custom-tool v1.0.0
#   Metadata: OK
#   Methods: OK (parse, get_fingerprint)
#   Dependencies: OK
```

### Hot-Reload Development Workflow

```bash
# 1. Create adapter in user directory (no reinstall needed)
cp scripts/core/adapters/trivy_adapter.py ~/.jmo/adapters/snyk_adapter.py

# 2. Edit and test iteratively
vim ~/.jmo/adapters/snyk_adapter.py
pytest tests/adapters/test_snyk_adapter.py -v  # Auto-reloads

# 3. Run scans with updated adapter
jmo scan --repo ./myapp --tools snyk

# 4. When ready, move to core adapters
mv ~/.jmo/adapters/snyk_adapter.py scripts/core/adapters/
```

### CommonFinding Schema (v1.2.0)

All adapters must output findings conforming to CommonFinding v1.2.0:

```python
Finding(
    schemaVersion="1.2.0",    # Required
    id="",                     # Auto-generated fingerprint
    ruleId="TOOL-RULE-ID",    # Tool-specific rule ID
    severity="HIGH",          # CRITICAL|HIGH|MEDIUM|LOW|INFO
    tool={                    # Tool metadata
        "name": "tool-name",
        "version": "1.0.0"
    },
    location={                # Finding location
        "path": "src/app.py",
        "startLine": 42,
        "endLine": 42
    },
    message="Short description",
    description="Detailed explanation",
    remediation="How to fix",
    references=[{"url": "https://..."}],
    raw={}                    # Original tool output for debugging
)
```

**Schema reference:** [docs/schemas/common_finding.v1.json](docs/schemas/common_finding.v1.json)

### Severity Mapping

JMo Security provides centralized severity mapping via `map_tool_severity()` in `scripts/core/common_finding.py`. This eliminates duplicated severity mapping logic across adapters and ensures consistent normalization.

**Available Mappings:**

| Tool | Tool Severity Values | CommonFinding Mapping |
|------|---------------------|----------------------|
| ZAP | informational, low, medium, high, critical | INFO, LOW, MEDIUM, HIGH, CRITICAL |
| Semgrep | error, warning, info | HIGH, MEDIUM, LOW |
| Nuclei | info, low, medium, high, critical, unknown | INFO, LOW, MEDIUM, HIGH, CRITICAL, INFO |
| Falco | emergency, alert, critical, error, warning, notice, informational, debug | CRITICAL, CRITICAL, CRITICAL, HIGH, MEDIUM, LOW, INFO, INFO |

**Usage in Adapters:**

```python
from scripts.core.common_finding import map_tool_severity

# Tool-specific mapping (uses TOOL_SEVERITY_MAPPINGS)
severity = map_tool_severity("zap", "informational")  # Returns "INFO"
severity = map_tool_severity("semgrep", "ERROR")      # Returns "HIGH"
severity = map_tool_severity("nuclei", "critical")    # Returns "CRITICAL"
severity = map_tool_severity("falco", "warning")      # Returns "MEDIUM"

# Unknown tools fall back to generic normalize_severity()
severity = map_tool_severity("unknown_tool", "HIGH")  # Returns "HIGH"
severity = map_tool_severity("unknown_tool", "ERROR") # Returns "HIGH" (common alias)
```

**Adding New Tool Mappings:**

To add severity mappings for a new tool, update `TOOL_SEVERITY_MAPPINGS` in `scripts/core/common_finding.py`:

```python
TOOL_SEVERITY_MAPPINGS: dict[str, dict[str, str]] = {
    # ... existing mappings ...
    "newtool": {
        "critical": "CRITICAL",
        "high": "HIGH",
        "moderate": "MEDIUM",  # Tool-specific terminology
        "low": "LOW",
        "informational": "INFO",
    },
}
```

### Advanced: Programmatic Plugin Management

```python
from scripts.core.plugin_loader import get_plugin_registry, get_available_adapters

# Get lazy-loading registry
registry = get_plugin_registry()

# List available adapters (without loading them)
available = get_available_adapters()
print(f"Available adapters: {available}")

# Get a specific adapter (lazy-loads on first access)
trivy_adapter = registry.get("trivy")
if trivy_adapter:
    meta = registry.get_metadata("trivy")
    print(f"{meta.name} v{meta.version}: {meta.description}")

# List currently loaded plugins
for name in registry.list_plugins():
    meta = registry.get_metadata(name)
    print(f"{meta.name} v{meta.version}")
```

### Checklist for New Adapters

- [ ] Adapter file created in `scripts/core/adapters/<tool>_adapter.py`
- [ ] Uses `@adapter_plugin` decorator with complete `PluginMetadata`
- [ ] Implements `parse()` method returning `List[Finding]`
- [ ] Uses `map_tool_severity()` for severity normalization (add to `TOOL_SEVERITY_MAPPINGS` if needed)
- [ ] `metadata.name` uses underscores, matching adapter filename (e.g., `dependency_check_adapter.py` → `"dependency_check"`)
- [ ] Tests added in `tests/adapters/test_<tool>_adapter.py`
- [ ] Validation passes: `jmo adapters validate`
- [ ] Integration test with real tool output
- [ ] Documentation updated if adding to official adapters

**Complete user guide:** [docs/USER_GUIDE.md — Plugin System](docs/USER_GUIDE.md#plugin-system)

## Tests

- Tests live in `tests/`.
- Use temporary paths and fabricated JSON for adapters per existing patterns.
- CI enforces coverage (see `.github/workflows/ci.yml`).

### Coverage reporting (Codecov)

We use Codecov via GitHub Actions with tokenless uploads (OIDC) on public repos. For maintainers, the quickest path is:

1. Sign in to <https://codecov.io> with your GitHub account.
2. Ensure a `main` branch test run completes (uploads `coverage.xml`).
3. The `codecov.yml` in the repo sets statuses to informational.
4. Optional: add `CODECOV_TOKEN` only if Codecov explicitly recommends it (public repos usually don’t need it). OIDC may also be enabled in Codecov org settings.

## Documentation

- User docs are in `docs/`.
- Screenshots: see `docs/internal/screenshots/README.md`; use `make screenshots-demo` for quick updates.
- Keep `README.md`, `QUICKSTART.md`, and `SAMPLE_OUTPUTS.md` aligned with fixtures.

## Building and Releasing

### Building Distribution Packages

Before releasing, you can build and verify packages locally:

```bash
# Build sdist and wheel
make dist

# Verify packages are installable (creates temp venv, installs, tests CLI)
make dist-verify

# Clean build artifacts
make dist-clean
```

The `dist-verify` target:

1. Creates a temporary virtual environment
2. Installs the built wheel
3. Verifies `jmo --version` and `jmo --help` work
4. Cleans up the temp environment

### Releasing (PyPI)

- Version is defined in `pyproject.toml` under `[project] version`.
- CI publishes on tags matching `v*` (see `.github/workflows/release.yml`).
- Steps to publish:
  1. Bump the version in `pyproject.toml`.
  2. Commit with a message like `release: vX.Y.Z` and create a tag: `git tag vX.Y.Z && git push --tags`.
  3. Ensure the project is configured as a Trusted Publisher in PyPI for this GitHub repo (no `PYPI_API_TOKEN` required). The workflow uses OIDC with `pypa/gh-action-pypi-publish@v1`.

### Workspace Cleanup

After development or before releases, clean up build artifacts:

```bash
# Quick clean (Python caches only)
make clean

# Full cleanup (caches + build + test + samples)
make clean-all

# Individual cleanup targets
make clean-build   # Build artifacts only
make clean-test    # Test artifacts only
make clean-caches  # Python caches only
```

Note: Virtual environments (`.venv/`) are preserved by `clean-all`. To remove stale venvs, manually delete: `venv-*/`, `.venv-pypi/`, `.post-release-venv/`.

## Communication

- Issues for bugs and features.
- Discussions for ideas and Q&A (enable in repo settings if not present).

---

## About the Maintainer

This project was built by **James (Jimmy) Moceri** as a capstone for the **Institute of Data × Michigan Tech University Cybersecurity Bootcamp** (graduated October 2025). The project evolved from a 1-week learning exercise into a production-grade security platform with 2,981 tests, 87% coverage, multi-target scanning, and 6-framework compliance automation.

**v1.0.0 Highlights:**

- 28 security scanners with plugin adapter architecture
- SQLite historical storage for trend analysis
- Machine-readable diffs for CI/CD integration
- Cross-tool deduplication (30-40% noise reduction)
- 4 unified scan profiles (fast/slim/balanced/deep)

**Professional Background:**

- 12+ years operational management & leadership (process optimization, team development, strategic planning)
- Cybersecurity Bootcamp graduate (OSINT, SIEM, vulnerability assessment, penetration testing, NIST RMF)
- CCSP (Certified Cyber Security Professional) certification in progress

**Currently seeking:** Security Engineering, DevSecOps, Application Security, or SOC Analyst roles where I can leverage this unique combination of operational leadership + security engineering expertise.

**Let's connect:** [LinkedIn](https://linkedin.com/in/jimmy-moceri) | [GitHub](https://github.com/jimmy058910)

Thanks again for contributing!

---

**Last Updated:** December 2025
