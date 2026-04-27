---
title: Testing Infrastructure & Patterns
paths:
  - tests/**/*.py
  - pyproject.toml
  - Makefile
references:
  - TEST.md (complete testing guide)
  - testing.cross-platform.rules.md (Windows/macOS/Linux compatibility)
  - pytest-timeout, pytest-xdist configuration
---

# Testing Infrastructure & Patterns

**What this covers:** Test organization, pytest command patterns, mocking strategies, and coverage requirements. For cross-platform Windows/macOS/Linux issues, see [testing.cross-platform.rules.md](testing.cross-platform.rules.md).

## Test Coverage & CI Requirements

**Mandatory:** `pytest --cov-fail-under=85` in CI.

- All new code must include tests.
- Aim for >87% coverage (current baseline).
- Use `--cov=scripts --cov-report=term-missing` to identify gaps.

## Running Tests Locally

```bash
# Recommended: Parallel execution (3-5x faster)
make test-fast                          # Fastest dev loop (no coverage)
make test-parallel                      # With coverage (CI-like)
pytest -n auto tests/unit/              # Direct pytest with parallelism

# Sequential (original, for debugging)
make test                               # Full coverage report
pytest tests/adapters/ -v               # Adapter tests only
pytest tests/cli/ -v                    # CLI tests only
```

## Test Markers

Use pytest markers to categorize and filter tests:

```python
@pytest.mark.slow           # Long-running tests (>5s)
@pytest.mark.requires_tools # Needs external tools installed
@pytest.mark.docker         # Requires Docker daemon
@pytest.mark.smoke          # Basic functionality check
```

**CI excludes these via:** `-m "not smoke and not requires_tools and not docker and not slow"`.

## Mocking Subprocess

**Rule:** Always mock `subprocess.run` for tests calling external commands.

```python
from unittest.mock import patch
from tests.conftest import mock_subprocess_success

with (
    patch("module.tool_exists", return_value=True),
    patch("module.find_tool", return_value="/usr/bin/tool"),
    patch("subprocess.run") as mock_run,
):
    mock_run.return_value = mock_subprocess_success(returncode=0)
    # ... test code ...
```

**Why:** Tests should not depend on external tools being installed. Real-tool tests get `@pytest.mark.requires_tools`.

## Mocking ToolInstaller (CRITICAL on Windows)

**Rule:** Always mock `ToolInstaller` in tests to prevent real installations.

```python
@patch("scripts.cli.tool_installer.ToolInstaller")
def test_scan_with_missing_tool(mock_installer):
    # Real installs spawn cmd.exe/node.exe that hang on Windows
    pass
```

## Timeout Configuration

- All tests have a **120s timeout** by default (configurable in `pyproject.toml`).
- Use `@pytest.mark.timeout(300)` for legitimately slow tests.
- Set `PYTEST_TIMEOUT=0` to disable during local debugging.

## Test File Organization

```text
tests/
├── unit/                   # Fast, self-contained
├── adapters/               # Adapter-specific (test_*_adapter.py)
├── reporters/              # Reporter-specific
├── cli/                    # CLI commands
├── integration/            # Multi-component scenarios
├── conftest.py             # Shared fixtures, markers, helpers
├── fixtures/               # Fixture data (JSON, YAML, etc.)
└── e2e/                    # End-to-end with real tools
```

**Reference:** [TEST.md](../../TEST.md) for the complete testing guide.

## `--maxfail` Truncation & Bug Archeology

The Nightly Extended Tests pytest invocation uses `--maxfail=20` (raised from 5 in v1.0.5; cross-platform jobs likewise). **This historically created a "bug archeology" pattern where deeper test failures were invisible until shallower ones were fixed** — most acute at the lower threshold.

When iterating on test fixes for nightly:

1. Each fix-and-validate cycle can reveal NEW failures from deeper in pytest's alphabetical order — failures that were always there but masked by the truncation cutoff.
2. Don't assume "it's just one bug left" until a clean run with 0 failures actually happens.
3. Each layer typically takes its own targeted fix PR; the post-v1.0.3 stabilization went through 5 such layers at `--maxfail=5` (PRs #343 → #344 → #345 → #346 → #347). v1.0.5 raised the cap to 20 to make this much rarer in practice.

**v1.0.5 mitigations** (PR shipping `--maxfail=20`):

- Added `--json-report --json-report-file=pytest-report.json` to nightly-extended-tests.
- Added a `Summarize pytest failures` step that renders the full failure list (capped at 50 entries to fit GHA's ~1MB Summary cap) into the run's `$GITHUB_STEP_SUMMARY`. So when truncation does happen, every caught failure is still visible in one place with its traceback.
- `pytest-report.json` is now also archived in the `nightly-test-results-${{ github.run_id }}` artifact bundle for fully post-hoc analysis.

**Iterating efficiently** — manual workflow dispatch instead of waiting for cron:

```bash
# Trigger Nightly Extended Tests on demand (~12-15 min vs 24 h cron)
gh workflow run scheduled.yml --ref main -f task=nightly

# Watch for completion
gh run list --workflow scheduled.yml --event workflow_dispatch --limit 1
```

The `task=nightly` input gates `nightly-extended-tests` and `lint-full` jobs in `scheduled.yml`. Other `task` choices: `e2e`, `performance`, `docker`, `all`.

**Diagnosing a truncated run:** If pytest output ends with `=== N failed in M.Ns ===` and N == 20 (or 5 on smoke / 3 on requires_tools), you're at the truncation cap. The Summary tab on the run page should list all N captured failures. Fix the visible ones, dispatch again, repeat until N drops below the cap or hits 0.

## Test Threshold Drift After Profile Changes

When changing `PROFILE_TOOLS` (or `MANUAL_INSTALL_TOOLS`) in `scripts/core/tool_registry.py`, several test/workflow constants need cascading updates:

- `tests/e2e/test_docker_workflows.py::DOCKER_VARIANTS` (per-variant `expected_tools` count)
- `tests/e2e/test_docker_workflows.py::DEEP_EXPECTED_TOOLS`, `BALANCED_EXPECTED_TOOLS`, etc. (named tool lists)
- `tests/e2e/test_docker_workflows.py::DEEP_ONLY_TOOLS` (tools that should NOT appear in lighter variants)
- `.github/workflows/scheduled.yml`'s `validate-variants` matrix (`expected_tools: <N>`)

Bearer's removal in PR #262 (April 2026) needed cascading updates that took multiple follow-up PRs to fully sync. **When changing `PROFILE_TOOLS`, grep for variant counts (`14`, `18`, `25`) and `expected_tools` simultaneously across `tests/` and `.github/workflows/`.**
