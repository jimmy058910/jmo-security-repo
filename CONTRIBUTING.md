# Contributing to JMo Security

Thanks for your interest in contributing! This project started as a Cybersecurity Capstone and has grown into a general-purpose security audit toolkit. Contributions of all kinds are welcome—code, docs, tests, examples, and issue triage.

## Code of Conduct

Be respectful and constructive. We expect contributors to follow a standard code of conduct. If issues arise, contact the maintainer.

## How to get started

- Good first issues: https://github.com/jimmy058910/jmo-security-repo/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22
- Browse open issues: https://github.com/jimmy058910/jmo-security-repo/issues
- Ask questions by opening a discussion or issue.

## Development setup

- Python 3.8+
- Recommended commands:

```bash
make dev-deps     # install Python dev dependencies
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
- Open a PR and fill out the template (if present). Link related issues.

## Coding standards

- Python: Ruff for linting (`ruff check`) and `ruff format`/`black` for formatting.
- Shell: `shellcheck` and `shfmt -i 2 -ci -bn`.
- Keep public CLI flags and outputs stable; update docs/tests when behavior changes.

## Tests

- Tests live in `tests/`.
- Use temporary paths and fabricated JSON for adapters per existing patterns.
- CI enforces coverage (see `.github/workflows/tests.yml`).

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
  3. Ensure `PYPI_API_TOKEN` is configured in repo secrets.

## Communication

- Issues for bugs and features.
- Discussions for ideas and Q&A (enable in repo settings if not present).

Thanks again for contributing!
