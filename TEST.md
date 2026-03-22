# Testing Guide

This document explains how to run tests, coverage, linting, and selected end-to-end checks locally and in CI.

## Prerequisites

- Python 3.12+ required (project venv is configured automatically by the editor)
- Install dev dependencies:

```bash
make dev-deps
```

- Optional security tools for full local CI:

```bash
jmo tools install --profile balanced  # Install security scanners
```

## Unit & Integration Tests

Run the test suite with coverage:

```bash
# Recommended: Parallel execution (3-5x faster)
make test-fast               # Parallel, no coverage, skip slow (fastest dev loop)
make test-parallel           # Parallel with coverage (CI-like)
pytest -n auto tests/        # Direct pytest with auto-detected workers

# Sequential execution
make test                    # Sequential with coverage (original)
pytest tests/                # ALL tests including slow e2e
pytest tests/ -m "slow"      # Only slow tests
```

- **Parallel tests** use `pytest-xdist` (`-n auto`) to utilize all CPU cores
- `make test-fast` is recommended for development (~5 min vs ~15-20 min sequential)
- `make test` excludes `smoke` and `requires_tools` markers by default (matches CI behavior)
- Outputs show a coverage summary (threshold in CI is 85%)
- Coverage config is defined in `pyproject.toml` under `[tool.coverage]`

### Test Configuration

- **pytest-xdist**: Parallel test execution using `-n auto` (auto-detects CPU cores). Install: `pip install pytest-xdist`.
- **pytest-timeout**: All tests have a 120-second timeout (configurable in `pyproject.toml`). Use `@pytest.mark.timeout(300)` for legitimately slow tests.
- **Slow tests**: Tests marked with `@pytest.mark.slow` can be excluded with `-m "not slow"`.
- **Cross-platform**: Tests must pass on Windows, Linux, and macOS. See `CLAUDE.md` for cross-platform testing guidelines.

## Linting & Security Checks

```bash
make fmt     # format (shfmt, black if installed, ruff-format)
make lint    # lint (shellcheck, ruff, bandit)
```

Notes:

- If ruff/bandit/shellcheck are missing, install via `pip install ruff bandit` or `jmo tools install`.

## Optional Test Dependencies

Some test modules require optional dependencies and will be **automatically skipped** if not installed:

| Test Module | Required Package | Install Command |
|-------------|------------------|-----------------|
| `tests/jmo_mcp/` | MCP SDK + pydantic v2 | `pip install "jmo-security[mcp]"` or `pip install "mcp[cli]>=1.0.0" "pydantic>=2.11.0"` |
| `tests/adapters/test_adapter_fuzzing.py` | Hypothesis | `pip install hypothesis` |

**Note:** If you see collection errors like `cannot import name 'TypeAdapter' from 'pydantic'`, upgrade pydantic: `pip install "pydantic>=2.11.0"`

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

## Comprehensive E2E Test Suite

The E2E suite lives in `tests/e2e/` and uses pytest. All tests replaced the legacy bash scripts after parity was confirmed.

### Quick Start

```bash
# Run full E2E suite
make test-e2e

# Run specific workflow file
pytest tests/e2e/test_scan_workflows.py -v

# Run specific test by ID (e.g., U1, U9, A1)
pytest tests/e2e/ -k "U1" -v

# Run Docker-based tests only
pytest tests/e2e/ -m docker -v

# Skip Docker tests (default for local dev)
pytest tests/e2e/ -m "not docker" -v
```

### Test Files

| File | Tests | Coverage |
|------|-------|---------|
| `test_scan_workflows.py` | U1-U6, M1-M3, W1 | Repo, image, IaC, multi-target, wizard scans |
| `test_wizard_workflows.py` | M4, W2 | Wizard emit-script, non-interactive wizard |
| `test_ci_gating.py` | U12 | CI mode exit codes, severity thresholds |
| `test_advanced_targets.py` | A1-A3 | GitLab, Kubernetes, deep profile |
| `test_docker_workflows.py` | U9-U11, M5-M6, W3-W4 | Docker-based scanning variants |
| `test_cross_platform.py` | - | Cross-platform compatibility |
| `test_linux_specific.py` | - | Linux-only features |
| `test_macos_specific.py` | - | macOS-only features |
| `test_windows_specific.py` | - | Windows-only features |

### Test Fixtures

Fixtures live in `tests/e2e/fixtures/` and are loaded automatically via `conftest.py`:

```text
tests/e2e/fixtures/
├── iac/         # Terraform + K8s + Dockerfiles with CIS violations
├── python/      # Flask app with OWASP Top 10 vulnerabilities
├── javascript/  # Node.js app with vulnerable dependencies
└── configs/     # Hardcoded secrets, API keys
```

### CI/CD Integration

The comprehensive test suite runs automatically in CI:

- **On PRs:** Fast profile tests (10-15 minutes)
- **Nightly:** Full test suite on Ubuntu + macOS (2-3 hours)
- **On Demand:** Manual workflow with specific test selection

See [.github/workflows/scheduled.yml](.github/workflows/scheduled.yml) for test execution details.

### Success Criteria

For release readiness:

- **≥95% success rate** (24/25 tests passing)
- **All Tier 1 tests pass** (repos, images, multi-target)
- **Zero CRITICAL issues** in test suite
- **Performance within bounds** (fast ≤10min, balanced ≤20min, deep ≤60min)

### Troubleshooting

**Test failures:**

```bash
# Re-run specific test with verbose output
pytest tests/e2e/ -k "U1" -v -s

# Verify tool installations
jmo tools check --profile balanced
jmo tools install --profile balanced
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
# Verify fixtures exist
ls -la tests/e2e/fixtures/iac/
ls -la tests/e2e/fixtures/python/
```

For comprehensive test plan details, see [docs/archive/v0.6.0/COMPREHENSIVE_TEST_PLAN.md](docs/archive/v0.6.0/COMPREHENSIVE_TEST_PLAN.md).

## CI

- GitHub Actions workflow `.github/workflows/ci.yml` enforces coverage ≥85%.
- The workflow installs dev dependencies and runs `pytest` with coverage.

### Test Sharding

CI uses **pytest-split** to distribute 5,000+ tests across 4 parallel shards for ~60% faster execution:

- **Sharded tests**: Ubuntu/Python 3.12 (primary CI target) runs tests in 4 parallel jobs
- **Matrix tests**: Other OS/Python combinations run full test suite sequentially
- **Coverage aggregation**: Coverage from all shards is merged before upload to Codecov

To run tests locally with sharding (for debugging CI issues):

```bash
# Run specific shard (1-4)
pytest tests/ --splits 4 --group 1 -m "not smoke and not requires_tools"

# Generate test durations for optimal splitting
pytest tests/ --store-durations --durations-path=.test_durations
```

## General Troubleshooting

- Missing tools: run `jmo tools check` and `jmo tools install --profile balanced`.
- PATH issues: ensure `~/.local/bin` is in your PATH if using pip --user installs.
- Coverage too low: add tests or temporarily adjust `pyproject.toml [tool.coverage]` (prefer adding tests).
- Different Python version: tests target 3.12 in CI; using older versions may cause minor differences.

### Import errors like `ModuleNotFoundError: No module named 'scripts'`

This repo ships as a Python package (entry point `jmo = scripts.cli.jmo:main`).
When running tests locally, install the package in editable mode so imports work:

```bash
make dev-setup  # or: python -m pip install -r requirements-dev.txt && python -m pip install -e .
```

Alternatively, you can set `PYTHONPATH=.` for ad-hoc runs, but installing with `-e .` matches CI and is recommended.

---

Happy testing!
