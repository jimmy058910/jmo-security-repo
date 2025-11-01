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
- Recommended commands:

```bash
make dev-deps     # install Python dev dependencies
make pre-commit-install  # install git hooks (YAML + Actions validation, etc.)
make verify-env   # check OS/WSL/macOS & external tool availability
make test         # run unit tests and coverage
make fmt && make lint
```

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

- Install curated tools (trufflehog, semgrep, trivy, syft, checkov, bandit, hadolint, OWASP ZAP, Falco, AFL++, etc.):

```bash
make tools
```

- Upgrade/refresh installed tools in place:

```bash
make tools-upgrade
# or directly:
bash scripts/dev/install_tools.sh --upgrade
```

- Targeted updates (user-local):

```bash
bash scripts/dev/update_tools.sh trufflehog
bash scripts/dev/update_tools.sh trivy
```

- Verify your environment at any time:

```bash
make verify-env
```

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

These checks run automatically on commit and are also enforced in CI (note: the Bandit hook is skipped in CI’s pre-commit stage; see `.github/workflows/tests.yml`).

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

- Basic workflow:

```bash
python3 scripts/cli/jmo.py scan --repos-dir ~/repos --human-logs
python3 scripts/cli/jmo.py report ./results --profile --human-logs
```

- Demo workflow (no external scanners required):

```bash
make screenshots-demo
```

## Docker local testing

Before publishing Docker images to GHCR, test them locally to validate changes:

### Build local images

```bash
# Build all variants (full/slim/alpine)
make docker-build-local

# Or build specific variant
docker build -t jmo-security:local-full -f Dockerfile .
```

### Test local images

```bash
# Test CLI works
docker run --rm jmo-security:local-full --help
docker run --rm jmo-security:local-full ci --help

# Test scan with volume mount
docker run --rm \
  -v $(pwd):/scan \
  -v $(pwd)/results:/results \
  jmo-security:local-full ci \
  --repo /scan \
  --results-dir /results \
  --profile-name fast \
  --allow-missing-tools
```

### Run E2E tests with local images

```bash
# Set environment variables to use local images
export DOCKER_IMAGE_BASE="jmo-security"
export DOCKER_TAG="local"

# Run specific Docker tests
bash tests/e2e/run_comprehensive_tests.sh --test U9
bash tests/e2e/run_comprehensive_tests.sh --test U10
bash tests/e2e/run_comprehensive_tests.sh --test U11

# Or run full suite
bash tests/e2e/run_comprehensive_tests.sh
```

### Pre-release Docker checklist

Before pushing Docker images:

- [ ] Build all three variants locally
- [ ] Test CLI works (`--help`, `scan --help`, `ci --help`)
- [ ] Test single repo scan
- [ ] Test multi-target scan (v0.6.0+ feature)
- [ ] Run E2E tests U9, U10, U11 with local images
- [ ] Verify image sizes are reasonable

## Package Manager Testing (v0.9.0+)

Before submitting Homebrew/WinGet PRs, test the packages locally.

### Test Homebrew Formula

```bash
# Install from local formula
brew install --build-from-source packaging/homebrew/jmo-security.rb

# Verify installation
jmo --help
jmo scan --help

# Verify wrapper commands work
jmotools wizard --help
jmotools fast --help

# Run formula tests
brew test jmo-security

# Audit formula (checks best practices)
brew audit --strict --online jmo-security

# Test upgrade path (if updating existing formula)
brew upgrade jmo-security

# Cleanup
brew uninstall jmo-security
```

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
- [ ] Verify CLI works (`jmo --help`, `jmotools wizard --help`)
- [ ] Test upgrade path from previous version
- [ ] Run `brew audit` (macOS) or `wingetcreate validate` (Windows)
- [ ] Verify all dependencies bundled correctly
- [ ] Test on fresh system (VM or Docker container)
- [ ] Check package size is reasonable

**Complete packaging guide:** [packaging/README.md](packaging/README.md) | [packaging/TESTING.md](packaging/TESTING.md)

## Git workflow

- Create a feature branch from `main`.
- Keep diffs small and focused.
- Write/update tests when changing behavior.
- Run `make fmt && make lint && make test` before pushing.
- Run `make pre-commit-run` to apply YAML linting and validate GitHub Actions workflows via actionlint.
- Open a PR and fill out the template (if present). Link related issues.
  - CI runs on a matrix (OS/Python). Workflows use concurrency to cancel redundant runs and set 20-minute timeouts per job.

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

## Coding standards

- Python: Ruff for linting (`ruff check`) and `ruff format`/`black` for formatting.
- Shell: `shellcheck` and `shfmt -i 2 -ci -bn`.
- YAML: `yamllint` via pre-commit; GitHub Actions validated by `actionlint` (also enforced in CI).
- Keep public CLI flags and outputs stable; update docs/tests when behavior changes.

## Tests

- Tests live in `tests/`.
- Use temporary paths and fabricated JSON for adapters per existing patterns.
- CI enforces coverage (see `.github/workflows/tests.yml`).

### Coverage reporting (Codecov)

We use Codecov via GitHub Actions with tokenless uploads (OIDC) on public repos. For maintainers, the quickest path is:

1. Sign in to <https://codecov.io> with your GitHub account.
2. Ensure a `main` branch test run completes (uploads `coverage.xml`).
3. The `codecov.yml` in the repo sets statuses to informational.
4. Optional: add `CODECOV_TOKEN` only if Codecov explicitly recommends it (public repos usually don’t need it). OIDC may also be enabled in Codecov org settings.

## Documentation

- User docs are in `docs/`.
- Screenshots: see `docs/screenshots/README.md`; use `make screenshots-demo` for quick updates.
- Keep `README.md`, `QUICKSTART.md`, and `SAMPLE_OUTPUTS.md` aligned with fixtures.

## Releasing (PyPI)

- Version is defined in `pyproject.toml` under `[project] version`.
- CI publishes on tags matching `v*` (see `.github/workflows/release.yml`).
- Steps to publish:
  1. Bump the version in `pyproject.toml`.
  2. Commit with a message like `release: vX.Y.Z` and create a tag: `git tag vX.Y.Z && git push --tags`.
  3. Ensure the project is configured as a Trusted Publisher in PyPI for this GitHub repo (no `PYPI_API_TOKEN` required). The workflow uses OIDC with `pypa/gh-action-pypi-publish@v1`.

## Communication

- Issues for bugs and features.
- Discussions for ideas and Q&A (enable in repo settings if not present).

---

## About the Maintainer

This project was built by **James (Jimmy) Moceri** as a capstone for the **Institute of Data × Michigan Tech University Cybersecurity Bootcamp** (graduated October 2025). The project evolved from a 1-week learning exercise into a production-grade security platform with 91% test coverage, multi-target scanning, and 6-framework compliance automation.

**Professional Background:**

- 12+ years operational management & leadership (process optimization, team development, strategic planning)
- Cybersecurity Bootcamp graduate (OSINT, SIEM, vulnerability assessment, penetration testing, NIST RMF)
- CCSP (Certified Cyber Security Professional) certification in progress

**Currently seeking:** Security Engineering, DevSecOps, Application Security, or SOC Analyst roles where I can leverage this unique combination of operational leadership + security engineering expertise.

**Let's connect:** [LinkedIn](https://linkedin.com/in/jimmy-moceri) | [GitHub](https://github.com/jimmy058910)

Thanks again for contributing!
