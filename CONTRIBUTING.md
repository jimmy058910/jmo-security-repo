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

## Git workflow

- Create a feature branch from `main`.
- Keep diffs small and focused.
- Write/update tests when changing behavior.
- Run `make fmt && make lint && make test` before pushing.
- Run `make pre-commit-run` to apply YAML linting and validate GitHub Actions workflows via actionlint.
- Open a PR and fill out the template (if present). Link related issues.
  - CI runs on a matrix (OS/Python). Workflows use concurrency to cancel redundant runs and set 20-minute timeouts per job.

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

Thanks again for contributing!
