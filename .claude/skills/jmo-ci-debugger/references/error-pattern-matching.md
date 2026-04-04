# Error Pattern Matching Reference

Error pattern matching regex and log analysis patterns for diagnosing CI failures.

---

## Quick Pattern Matching Table

When diagnosing CI failures, match error messages to these patterns:

| Error Pattern (regex) | Failure | Section |
|----------------------|---------|---------|
| `invalid reference format` | Docker Tag Extraction | #1 |
| `fail_on_error is not valid` | Actionlint Parameters | #2 |
| `unknown flag: --version` | Docker Testing Command | #3 |
| `Resource not accessible` | SARIF Upload Permission | #4 |
| `Authentication failed\|401 Unauthorized` | Docker Hub README Sync | #5 |
| `ModuleNotFoundError` (multiple PRs) | Dependabot Cascading Failures | #6 |
| `MD036/no-emphasis-as-heading` | Markdownlint | #7 |
| `ruff\.+Failed` | Pre-commit Hooks | #8 |
| `Coverage of \d+% is below` | Test Coverage | #9 |
| `requirements-dev\.txt does not match` | Requirements Drift | #10 |
| `syntax error: expected <block` | YAML Syntax | #11 |
| `GH013: Repository rule violations` | Branch Protection | #12 |
| `waiting for status to be reported` | Rulesets/Commit Status | #13 |
| `lint-full.*Failed` (4+ tools) | Nightly Cascading Failures | #14 |
| `F401 imported but unused\|F541 f-string` | Ruff After Black | #15 |
| `assert 0\.\d+ [<>=]+ 0\.\d+` (across platforms) | Platform Float Precision | #16 |
| `FileNotFoundError.*React dashboard` | React Build Check | #17 |

---

## Log Analysis Commands

### Fetch Failed Run Logs

```bash
# Get failed run ID
gh run list --status=failure --limit 5

# View failed job logs
gh run view <run-id> --log-failed

# Filter for specific error patterns
gh run view <run-id> --log-failed | grep -E "Failed|error:|FAILED"

# Download full logs for analysis
gh run download <run-id> --dir ./ci-logs
```

### Categorize Failures

```bash
# Pipe failed logs into categories
gh run view <run-id> --log-failed > failures.txt

echo "=== Actionlint ==="
grep "actionlint" failures.txt

echo "=== Markdownlint ==="
grep "markdownlint" failures.txt

echo "=== Mypy ==="
grep "mypy" failures.txt

echo "=== Test Failures ==="
grep -E "FAILED|assert" failures.txt

echo "=== Import Errors ==="
grep -E "ModuleNotFoundError|ImportError" failures.txt

echo "=== Docker Errors ==="
grep -E "docker|image|tag|manifest" failures.txt

echo "=== Permission Errors ==="
grep -E "permission|accessible|unauthorized" failures.txt
```

### Cross-Platform Comparison

```bash
# Check if failure is platform-specific
# Look at all 6 matrix jobs: Ubuntu x Python 3.10/3.11/3.12, macOS x Python 3.10/3.11/3.12

gh run view <run-id> --log-failed | grep -E "assert|FAILED" | grep -E "test_name"

# If only some platforms fail -> platform-specific issue (#16)
# If ALL platforms fail -> likely code bug or configuration issue
```

---

## Regex Patterns for Common Errors

### Python Test Failures

```regex
# Float comparison failures
assert\s+\d+\.\d+\s*[<>=!]+\s*\d+\.\d+

# Module import errors
ModuleNotFoundError:\s+No module named\s+'[\w.]+'

# Coverage threshold
Coverage of \d+% is below threshold of \d+%

# Test collection errors
ImportError while importing test module
```

### YAML/Workflow Errors

```regex
# YAML syntax
syntax error: expected <block\s+\w+>.*found.*<block\s+\w+>

# Actionlint
Unexpected input\(s\) '[\w_]+',\s*valid inputs are

# Workflow permissions
Resource not accessible by integration
refusing to allow.*without.*write permission
```

### Docker Errors

```regex
# Tag format
invalid reference format:?\s*v?\d+

# Manifest not found
manifest.*not found.*for\s+v?\d+

# Build failures
Error:.*docker\s+(build|push|pull)\s+failed
```

### Pre-commit Hook Failures

```regex
# General hook failure
\w+\.+Failed

# Ruff violations
F\d{3}\s+\[\*\]\s+.+

# Black formatting
would reformat\s+\S+\.py
```

---

## Diagnostic Decision Tree

```text
CI Failure
|
+-- Which job failed?
    |
    +-- quick-checks (2-3 min)
    |   |-- yamllint error -> #11 YAML Syntax
    |   |-- actionlint error -> #2 Actionlint Parameters
    |   |-- deps-compile mismatch -> #10 Requirements Drift
    |   +-- security guardrail -> Check for leaked secrets
    |
    +-- test-matrix (10-15 min)
    |   |-- ModuleNotFoundError (multiple PRs) -> #6 Dependabot
    |   |-- Coverage below 85% -> #9 Test Coverage
    |   |-- Float assertion failures -> #16 Platform Precision
    |   |-- FileNotFoundError: React -> #17 React Build Check
    |   +-- Other test failures -> Check test code
    |
    +-- lint-full (nightly)
    |   |-- 4+ tool failures -> #14 Nightly Cascading
    |   |-- markdownlint only -> #7 Markdownlint
    |   |-- ruff only -> #8 Pre-commit / #15 Ruff After Black
    |   +-- mypy only -> Check type annotations
    |
    +-- docker-build (release)
    |   |-- Tag format error -> #1 Docker Tags
    |   |-- --version flag error -> #3 Docker Testing
    |   +-- Build failure -> Check Dockerfile
    |
    +-- docker-scan (release)
    |   |-- Resource not accessible -> #4 SARIF Upload
    |   +-- CRITICAL vulnerability -> Review Trivy results
    |
    +-- docker-hub-readme (release)
    |   |-- Auth failed / 401 -> #5 Docker Hub
    |   +-- Not found -> Check DOCKERHUB_ENABLED variable
    |
    +-- Push rejected
        |-- GH013 rule violations -> #12 Branch Protection
        +-- Waiting for status -> #13 Rulesets/Commit Status
```

---

## Monitoring Commands

```bash
# Watch CI status in real-time
gh run watch

# List recent failed runs
gh run list --status=failure --limit 10

# Check PR check status
gh pr checks <pr-number>
gh pr checks <pr-number> --watch  # Real-time

# View workflow run details
gh run view <run-id>
gh run view <run-id> --log-failed

# Re-run failed jobs
gh run rerun <run-id> --failed
```
