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

## Comprehensive E2E Test Suite (v0.6.0+)

For thorough validation across all target types, OS platforms, and execution methods, use the comprehensive test suite:

### Quick Start

```bash
# Run full test suite for your OS (Ubuntu/macOS/Windows WSL2)
bash tests/e2e/run_comprehensive_tests.sh

# Run specific test
bash tests/e2e/run_comprehensive_tests.sh --test U1

# Generate HTML report from results
python tests/e2e/generate_report.py /tmp/jmo-comprehensive-tests-*/test-results.csv
```

### Test Matrix

The comprehensive suite tests **6 target types × 3 OS × 3 execution methods**:

**Target Types:**

- Repository scanning (existing functionality)
- Container image scanning (v0.6.0)
- IaC file scanning (v0.6.0)
- Web app/API scanning (v0.6.0)
- GitLab repository scanning (v0.6.0)
- Kubernetes cluster scanning (v0.6.0)

**Operating Systems:**

- Ubuntu 22.04 (12 tests)
- macOS 14 Sonoma (6 tests)
- Windows 11 WSL2 (4 tests)

**Execution Methods:**

- Native CLI (`jmo` command)
- Wizard (`jmotools wizard`)
- Docker containers (full/slim variants)

### Test Suites

**Ubuntu Test Suite (U1-U12):**

```bash
# Single repo scan (native CLI)
bash tests/e2e/run_comprehensive_tests.sh --test U1

# Container image scan
bash tests/e2e/run_comprehensive_tests.sh --test U2

# Multi-target scan (repo + image + IaC)
bash tests/e2e/run_comprehensive_tests.sh --test U5

# CI mode with severity gating
bash tests/e2e/run_comprehensive_tests.sh --test U12

# Docker-based scanning
bash tests/e2e/run_comprehensive_tests.sh --test U9
```

**Advanced Tests (A1-A3):**

```bash
# GitLab scanning (requires GITLAB_TOKEN)
export GITLAB_TOKEN=your-token
bash tests/e2e/run_comprehensive_tests.sh --test A1

# Kubernetes scanning (requires kubectl + cluster)
bash tests/e2e/run_comprehensive_tests.sh --test A2

# Deep profile with all 11 tools
bash tests/e2e/run_comprehensive_tests.sh --test A3
```

### Test Fixtures

The test suite uses realistic fixtures with known security issues:

```bash
# Setup test fixtures
bash tests/e2e/fixtures/setup_fixtures.sh

# Fixtures include:
# - IaC: Terraform with CIS violations, K8s privileged pods, bad Dockerfiles
# - Python: Flask app with OWASP Top 10 vulnerabilities
# - JavaScript: Node.js app with vulnerable dependencies
# - Configs: Hardcoded secrets, API keys
```

### CI/CD Integration

The comprehensive test suite runs automatically in CI:

- **On PRs:** Fast profile tests (10-15 minutes)
- **Nightly:** Full test suite on Ubuntu + macOS (2-3 hours)
- **On Demand:** Manual workflow with specific test selection

See [.github/workflows/ci.yml](.github/workflows/ci.yml) for test execution details.

### Test Results

Test results include:

- **CSV:** `test-results.csv` with test ID, status, duration
- **Logs:** Individual test logs in `{results_dir}/{test_id}/test.log`
- **Findings:** Scan outputs in `{results_dir}/{test_id}/summaries/findings.json`
- **Report:** Human-readable markdown report with statistics

**Example Report:**

```bash
python tests/e2e/generate_report.py /tmp/jmo-e2e-results-123/test-results.csv

# Output:
# ============================================================
# E2E Test Results Summary
# ============================================================
#
# Overall Statistics:
#   Total Tests:   12
#   ✅ Passed:      11
#   ❌ Failed:      1
#   ⏭️  Skipped:    0
#   Success Rate:  91.7%
#
# Results by Suite:
#   Ubuntu: 11/12 passed (1 failed, 0 skipped)
#
# ✅ RELEASE READY
# ============================================================
```

### Success Criteria

For release readiness:

- **≥95% success rate** (24/25 tests passing)
- **All Tier 1 tests pass** (repos, images, multi-target)
- **Zero CRITICAL issues** in test suite
- **Performance within bounds** (fast ≤10min, balanced ≤20min, deep ≤60min)

### Troubleshooting

**Test failures:**

```bash
# Check test log
cat /tmp/jmo-e2e-results-*/U1/test.log

# Re-run specific test with verbose output
bash tests/e2e/run_comprehensive_tests.sh --test U1

# Verify tool installations
make verify-env
make tools
```

**Docker tests failing:**

```bash
# Check Docker is running
docker ps

# Pull required images
docker pull alpine:3.19
docker pull ghcr.io/jimmy058910/jmo-security:latest-full

# Verify volume mounts work
docker run --rm -v $(pwd):/test alpine:3.19 ls /test
```

**Fixture issues:**

```bash
# Re-create fixtures
bash tests/e2e/fixtures/setup_fixtures.sh

# Verify fixtures exist
ls -la tests/e2e/fixtures/iac/
ls -la tests/e2e/fixtures/python/
```

For comprehensive test plan details, see [docs/archive/v0.6.0/COMPREHENSIVE_TEST_PLAN.md](docs/archive/v0.6.0/COMPREHENSIVE_TEST_PLAN.md).

## CI

- GitHub Actions workflow `.github/workflows/tests.yml` enforces coverage ≥85%.
- The workflow installs dev dependencies and runs `pytest` with coverage.

## General Troubleshooting

- Missing tools: run `make verify-env` and `make tools`.
- PATH issues: ensure `~/.local/bin` is in your PATH if using pip --user installs.
- Coverage too low: add tests or temporarily adjust `.coveragerc` (prefer adding tests).
- Different Python version: tests target 3.11 in CI; using older versions may cause minor differences.

### Import errors like `ModuleNotFoundError: No module named 'scripts'`

This repo ships as a Python package (entry point `jmo = scripts.cli.jmo:main`).
When running tests locally, install the package in editable mode so imports work:

```bash
make dev-setup  # or: python -m pip install -r requirements-dev.txt && python -m pip install -e .
```

Alternatively, you can set `PYTHONPATH=.` for ad-hoc runs, but installing with `-e .` matches CI and is recommended.

---

Happy testing!
