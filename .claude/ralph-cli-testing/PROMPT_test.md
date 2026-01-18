# Ralph CLI Testing - Test Discovery Mode

## Your Mission

Run the full test suite, analyze failures, and populate IMPLEMENTATION_PLAN.md with tasks.

## Workflow

### 1. Run Full Test Suite

```bash
python -m pytest tests/cli_ralph/ -v --tb=short
```

### 2. Analyze Results

For each failure, identify:
- **Test ID**: The test function name (e.g., `test_hv_001_version_output`)
- **Error message**: The actual vs expected output
- **Likely root cause**: What's causing the failure
- **Priority**: Critical (blocks other tests), High, Medium, or Enhancement

### 3. Create Issues

Add each failure to IMPLEMENTATION_PLAN.md using this format:

```markdown
### TASK-XXX: [Brief title describing the issue]
**Priority:** Critical | High | Medium | Enhancement
**Status:** Open
**Test:** [Test ID, e.g., test_df_003_json_diff]
**Error:**
```
[Paste the error message]
```
**Root Cause:** [Your analysis]
**Fix:** [Proposed solution]
```

### 4. Prioritize

Order tasks by:
1. **Critical**: Breaks multiple tests or core functionality
2. **High**: Single test failure, clear fix
3. **Medium**: Edge cases, minor issues
4. **Enhancement**: Improvements, not failures

### 5. Exit

After populating the plan, EXIT. Build mode will fix issues.

## JMo Security Context

This is the JMo Security Audit Tool Suite CLI test suite.

Test categories (94 total tests):
- `test_help_version.py` - Basic CLI help/version
- `test_tools_commands.py` - Tool management
- `test_tool_installation.py` - Tool installation (slow)
- `test_scan_execution.py` - Scan execution (slow)
- `test_adapters_commands.py` - Adapter operations
- `test_report_commands.py` - Report generation
- `test_history_commands.py` - History database
- `test_trends_commands.py` - Trend analysis
- `test_diff_commands.py` - Diff comparisons
- `test_policy_commands.py` - Policy enforcement
- `test_ci_mode.py` - CI/CD integration

## Notes

- Tests use fixtures from `.claude/ralph-cli-testing/fixtures/`
- History/trends tests use `--db` flag for test database
- Windows excludes some tools (falco, afl++, mobsf, akto)
- All tests should pass before starting build mode
