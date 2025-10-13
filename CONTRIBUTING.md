# Contributing to JMo Security

Thanks for your interest in contributing! This project started as a Cybersecurity Capstone and has grown into a general-purpose security audit toolkit. Contributions of all kinds are welcome—code, docs, tests, examples, and issue triage.

## Code of Conduct

Be respectful and constructive. We expect contributors to follow a standard code of conduct. If issues arise, contact the maintainer.

## How to get started

- Good first issues: https://github.com/jimmy058910/jmo-security-repo/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22
- Browse open issues: https://github.com/jimmy058910/jmo-security-repo/issues
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
1. Sign in to https://codecov.io with your GitHub account.
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
