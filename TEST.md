# Testing Guide

This document explains how to run tests, coverage, linting, and selected end-to-end checks locally and in CI.

## Prerequisites

- Python 3.11 recommended (project venv is configured automatically by the editor)
- Install dev dependencies:

```bash
make dev-deps
```

- Optional linters/tools for full local CI:

```bash
make tools  # installs shellcheck, shfmt, ruff, bandit, and curated scanners
```

## Unit & Integration Tests

Run the full test suite with coverage:

```bash
make test
```

- Outputs show a coverage summary (threshold in CI is 85%).
- Coverage config is defined in `.coveragerc`.

## Linting & Security Checks

```bash
make fmt     # format (shfmt, black if installed, ruff-format)
make lint    # lint (shellcheck, ruff, bandit)
```

Notes:
- If ruff/bandit/shellcheck are missing, install via `make tools`.

## End-to-End Smoke (optional)

To run a small smoke test using the CLI:

```bash
# Use a small set of repos or create a dummy repo directory
mkdir -p ~/smoke/repos/sample && cd ~/smoke/repos/sample && git init && cd -

# Scan with fast profile and human logs
python3 scripts/cli/jmo.py scan --repos-dir ~/smoke/repos --profile-name fast --human-logs

# Aggregate reports with profiling
python3 scripts/cli/jmo.py report ./results --profile --human-logs

# Open the dashboard
xdg-open results/summaries/dashboard.html  # mac: open
```

## CI

- GitHub Actions workflow `.github/workflows/tests.yml` enforces coverage ≥85%.
- The workflow installs dev dependencies and runs `pytest` with coverage.

## Troubleshooting

- Missing tools: run `make verify-env` and `make tools`.
- PATH issues: ensure `~/.local/bin` is in your PATH if using pip --user installs.
- Coverage too low: add tests or temporarily adjust `.coveragerc` (prefer adding tests).
- Different Python version: tests target 3.11 in CI; using older versions may cause minor differences.

---

Happy testing!
