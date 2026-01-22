# Ralph CLI Testing - Operational Guide

## Essential Commands

```bash
# Run tests (default)
python -m pytest tests/cli_ralph/ -v --tb=short

# Single test
python -m pytest tests/cli_ralph/test_help_version.py::test_version -v

# Skip slow tests
python -m pytest tests/cli_ralph/ -v -m "not slow"

# CLI commands
python -m scripts.cli.jmo --version
python -m scripts.cli.jmo tools check
python -m scripts.cli.jmo history list --db tools/ralph-testing/fixtures/test-history.db
```

## Commit Pattern

```bash
git add -A && git commit -m "test(wizard): description"
```

## Platform Notes (Windows)

- **Excluded tools:** falco, afl++, mobsf, akto
- **Tool paths:** Use `find_tool()`, not `shutil.which()` (OPA installs to `~/.jmo/bin/`)
- **HOME mocking:** Use `Path.home()` monkeypatch, not `HOME` env var

## Testing Infrastructure

- Fixtures: `tools/ralph-testing/fixtures/`
- Coverage target: `scripts/cli/wizard_flows/`
- Allow missing tools: `--allow-missing-tools`

## Cross-Iteration Learnings

Read `tools/ralph-testing/iteration-logs/learnings.txt` for discoveries from previous tasks.
Append new learnings after completing each task (max 3 per task).

## Current Status

- 94 tests, ~4 min runtime
- Tests: `tests/cli_ralph/*.py`
- Plan: `tools/ralph-testing/IMPLEMENTATION_PLAN.md`
