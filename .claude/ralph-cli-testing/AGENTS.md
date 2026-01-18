# Ralph CLI Testing - Operational Guide

Quick reference for commands, patterns, and learnings during Ralph Loop iterations.

## Test Commands

```bash
# Run all CLI tests
python -m pytest tests/cli_ralph/ -v --tb=short

# Run single test file
python -m pytest tests/cli_ralph/test_help_version.py -v

# Run specific test
python -m pytest tests/cli_ralph/test_diff_commands.py::TestDiffCommands::test_df_001_basic_diff -v

# Skip slow tests (tool installation, scans)
python -m pytest tests/cli_ralph/ -v -m "not slow"
```

## Database Tests

History and trends tests require the `--db` flag:

```bash
python -m scripts.cli.jmo history list --db .claude/ralph-cli-testing/fixtures/test-history.db
python -m scripts.cli.jmo trends show --db .claude/ralph-cli-testing/fixtures/test-history.db
```

## CLI Commands

```bash
# Version and help
python -m scripts.cli.jmo --version
python -m scripts.cli.jmo --help
python -m scripts.cli.jmo scan --help

# Tool management
python -m scripts.cli.jmo tools list
python -m scripts.cli.jmo tools check
```

## Commit Pattern

```bash
git add -A && git commit -m "fix(cli-tests): description of the fix"
```

## Operational Learnings

**Platform:**
- Windows excludes 4 tools: falco, afl++, mobsf, akto
- OPA installs to `~/.jmo/bin/` - use `find_tool()` not `shutil.which()`

**Test Infrastructure:**
- Fixtures in `.claude/ralph-cli-testing/fixtures/`
- Tests use `--allow-missing-tools` for graceful degradation
- 94 tests across 11 test files

**Current Status:**
- All 94 tests passing
- Test suite runs in ~4 minutes

## File Locations

| File | Purpose |
|------|---------|
| `tests/cli_ralph/*.py` | Test files (backpressure) |
| `.claude/ralph-cli-testing/fixtures/` | Test fixtures (results, DB) |
| `.claude/ralph-cli-testing/specs/` | Requirements specs |
| `IMPLEMENTATION_PLAN.md` | Task list (read AND update) |
