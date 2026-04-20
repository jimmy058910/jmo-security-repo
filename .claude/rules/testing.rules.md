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
