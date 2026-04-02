---
name: jmo-e2e-verify
description: >
  AI-orchestrated e2e verification with parallel sub-agents, intelligent failure
  analysis, and optional visual dashboard inspection. Runs JMo Security e2e tests,
  categorizes failures (flaky/infrastructure/regression/test-bug), and produces a
  structured markdown report. Optionally uses agent-browser for visual dashboard
  inspection. Recommends follow-on skills for discovered issues.
user-invocable: true
context: fork
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
argument-hint: "[quick|full|visual|scan-only]"
disable-model-invocation: false
---

## Execution

Verifying JMo Security e2e suite — mode: **$ARGUMENTS**

---

## Purpose

Orchestrate end-to-end verification of JMo Security with AI-driven analysis. Runs
pytest e2e tests, categorizes every failure, optionally inspects the HTML dashboard
visually, and produces an actionable report.

**Skill connections:**
- Failures categorized as `ci` → recommend `/jmo-ci-debugger`
- Untested code paths found → recommend `/jmo-test-fabricator`
- Dashboard rendering issues → recommend `/jmo-dashboard-builder`
- Report feeds `release-readiness` agent for release sign-off

---

## Scope Modes

| Mode | What Runs | Est. Duration |
|------|-----------|--------------|
| `quick` (default) | scan-workflows + ci-gating + visual spot-check | ~5 min |
| `full` | all e2e tests + full visual suite + Docker workflows | ~30-60 min |
| `visual` | dashboard visual tests only (pytest-playwright) | ~3 min |
| `scan-only` | real scan against fixtures, no assertions | ~2 min |

If `$ARGUMENTS` is empty, use `quick` mode.

---

## Phase 1 — Pre-flight (~30s)

**Goal:** Environment checks and scope determination before any tests run.

Steps:
1. Parse mode from `$ARGUMENTS`. Default to `quick` if blank or unrecognized.
2. Check environment:
   ```bash
   python --version                          # Must be >= 3.12
   pytest --version                          # Must be installed
   git -C . status --short                   # Capture dirty state
   git -C . log --oneline main...HEAD        # Commits being tested
   df -h . 2>/dev/null || dir               # Disk space (skip if unavailable)
   ```
3. Detect optional capabilities:
   - Docker: `docker info 2>/dev/null` → affects `full` mode Docker tests
   - agent-browser: `which agent-browser 2>/dev/null` → affects Phase 5
   - playwright: `python -m pytest tests/e2e/test_dashboard_visual.py --collect-only -q 2>/dev/null` → skip if import fails
4. Print pre-flight summary: mode, python version, optional caps detected/missing.
5. Abort with clear message if python < 3.12 or pytest not installed.

---

## Phase 2 — Parallel Research

**Goal:** Three concurrent sub-agents gather context to focus test execution and
pre-seed failure analysis. Run in parallel — do not wait for one before starting
another.

### Sub-agent A: Codebase Delta

```text
Task: Identify what changed since main branch and map to affected test categories.

Tools: Bash, Grep, Read

Steps:
1. git diff main...HEAD --name-only
2. Classify each changed file:
   - scripts/core/adapters/  → "adapter tests affected"
   - scripts/core/reporters/ → "reporter tests affected"
   - scripts/cli/            → "cli/wizard tests affected"
   - tests/e2e/              → "e2e fixture/conftest changes"
   - .github/workflows/      → "ci config changed (not testable)"
3. Output: list of affected test categories (scan-workflows, ci-gating,
   docker-workflows, wizard-workflows, advanced-targets) + files changed count.
```

### Sub-agent B: Test Health

```text
Task: Identify known flaky tests and recent CI failures.

Tools: Bash, Grep, Read

Steps:
1. grep -r "pytest.mark.flaky\|# FLAKY\|# flaky" tests/e2e/ --include="*.py" -l
2. grep -r "xfail\|skip" tests/e2e/ --include="*.py" -l
3. Read tests/e2e/conftest.py lines around KNOWN_FLAKY if it exists
4. Check for any .e2e-results.json from previous run: parse failed tests if present
5. Output: list of known-flaky test IDs, count of xfail/skip markers,
   most recent pass/fail status if cached results exist.
```

### Sub-agent C: Infrastructure

```text
Task: Verify test infrastructure is ready.

Tools: Bash, Read, Glob

Steps:
1. Check fixture directories exist:
   - tests/e2e/fixtures/iac/
   - tests/e2e/fixtures/python/
   - tests/e2e/fixtures/javascript/
2. Verify conftest.py present: tests/e2e/conftest.py
3. Check disk space > 500MB available (scan results need room)
4. If mode=full or mode=scan-only: verify jmo CLI is installed
   (python -m jmo --version or jmo --version)
5. If mode=full: check Docker availability (docker info)
6. Output: ready/not-ready per fixture dir, jmo installed y/n, Docker y/n,
   any blocking infrastructure gaps.
```

Synthesize sub-agent outputs before Phase 3:
- Log affected test categories (from A) → will skip unaffected in `quick` mode
- Log known flaky IDs (from B) → pre-seed failure analysis
- Log infrastructure gaps (from C) → skip tests requiring missing deps

---

## Phase 3 — Test Execution

**Goal:** Run the appropriate pytest test suite with live progress.

### Command Selection by Mode

**quick:**
```bash
pytest tests/e2e/test_scan_workflows.py tests/e2e/test_ci_gating.py \
  -m "e2e" --timeout=300 -v \
  --json-report --json-report-file=.e2e-results.json \
  -x 2>&1 | tee .e2e-output.txt
```

**full:**
```bash
pytest tests/e2e/ -m "e2e" --timeout=900 -v \
  --json-report --json-report-file=.e2e-results.json \
  2>&1 | tee .e2e-output.txt
```

**visual:**
```bash
pytest tests/e2e/test_dashboard_visual.py --timeout=120 -v \
  --json-report --json-report-file=.e2e-results.json \
  2>&1 | tee .e2e-output.txt
```

**scan-only:**
```bash
# Run a real scan against the Python fixtures dir, capture output only
jmo ci --repo tests/e2e/fixtures/python/ \
  --profile fast --allow-missing-tools \
  --results-dir /tmp/jmo-e2e-verify-scan/ \
  --human-logs 2>&1 | tee .e2e-output.txt
```

### Execution Notes

- Always use `shell=False` conceptually — pass as list when programmatic.
- If `pytest-json-report` not installed, omit `--json-report` flags and parse
  output text directly.
- If `--collect-only` returns 0 tests (fixture dirs missing), report and skip.
- Stream output live — do not buffer until completion.

---

## Phase 4 — Failure Analysis

**Goal:** Categorize every failing test. Provide fix suggestions with file:line refs.

### Failure Categories

| Category | Definition | Next Action |
|----------|------------|-------------|
| `environment` | Missing tool, Docker not running, fixture missing | Fix infra, not code |
| `flaky` | In known-flaky list OR matches flaky pattern | Retry or ignore |
| `regression` | Code change in Phase 2 delta broke a test | Must fix before release |
| `test-bug` | Test assertion is wrong, not the implementation | Fix test |

### Analysis Protocol

For each failed test:
1. Read the full traceback from `.e2e-output.txt` or `.e2e-results.json`.
2. Cross-reference test ID against known-flaky list from Phase 2.
3. Read the test source file at the failing line.
4. Read the implementation file implicated in the traceback (if any).
5. Apply category rules:

```text
IF error contains "FileNotFoundError" or "No such file" or "command not found":
  → category = environment
  → suggestion: "Install missing tool or restore fixture"

ELIF test_id in known_flaky_list:
  → category = flaky
  → suggestion: "Known flaky — retry or add @pytest.mark.flaky"

ELIF changed_files (from Phase 2) overlap with files in traceback:
  → category = regression
  → suggestion: Provide specific file:line where fix is needed

ELIF assertion error AND implementation looks correct:
  → category = test-bug
  → suggestion: "Update test assertion at <file>:<line>"

ELSE:
  → category = regression (default for unknowns)
```

6. For `regression` failures: read the git diff for the implicated file and
   suggest the minimal fix.

### Flaky Pattern Detection

Classify as flaky if traceback matches any:
- `TimeoutExpired` or `subprocess.TimeoutExpired`
- `ConnectionRefusedError`
- `TemporaryDirectory` or `/tmp/` permission errors
- `OSError: [Errno 28]` (no space left)
- Test name contains `test_real_tool` or `test_docker`
- Error message contains "rate limit" or "502" or "503"

---

## Phase 5 — Visual Verification

**Condition:** Run only if:
- mode is `quick`, `full`, or `visual` (not `scan-only`)
- agent-browser detected in Phase 1, OR pytest-playwright available

### Path A: pytest-playwright (CI-safe, all platforms)

Run if playwright available:
```bash
pytest tests/e2e/test_dashboard_visual.py \
  --timeout=120 -v 2>&1 | tee .e2e-visual.txt
```

Report: list each test (pass/fail), note any screenshot diff failures.

### Path B: agent-browser (AI visual reasoning, WSL/Linux/macOS only)

Run if agent-browser available AND not on native Windows:

1. Locate dashboard output: `results/dashboard.html` or `results/report.html`
   (check most recent results dir first).
2. If no dashboard found, generate one:
   ```bash
   jmo report results/ --format html --output /tmp/jmo-e2e-dashboard.html
   ```
3. Open with agent-browser:
   ```bash
   agent-browser open --allow-file-access "file:///tmp/jmo-e2e-dashboard.html"
   ```
4. Visually inspect (describe what you observe):
   - Do severity charts render with non-zero dimensions?
   - Is the findings table populated with rows?
   - Do compliance framework badges appear in the Compliance tab?
   - Does the SBOM tree show nodes?
   - Does severity filter reduce visible rows when clicked?
   - Are there any JS console errors?
5. Test responsive viewports:
   - Mobile: 375x812 — no horizontal overflow?
   - Tablet: 768x1024 — layout intact?
   - Desktop: 1440x900 — full layout visible?
6. Capture screenshots and note any rendering issues.

### Path C: Skip

If neither agent-browser nor playwright available, note in report:
> "Visual verification skipped — install pytest-playwright (`pip install pytest-playwright && playwright install chromium`) or agent-browser (`npm install -g agent-browser`) to enable."

---

## Phase 6 — Report Generation

**Goal:** Produce a structured markdown report summarizing all findings.

### Report Template

```markdown
# JMo Security E2E Verification Report

**Date:** <ISO timestamp>
**Mode:** <quick|full|visual|scan-only>
**Branch:** <git branch>
**Commits tested:** <count> commits since main

## Pre-flight Summary

- Python: <version> (OK / FAIL)
- pytest: <version> (OK / FAIL)
- Docker: <available / not available>
- agent-browser: <available / not available>
- playwright: <available / not available>

## Test Results

| Category | Passed | Failed | Skipped | Total |
|----------|--------|--------|---------|-------|
| scan-workflows | N | N | N | N |
| ci-gating | N | N | N | N |
| wizard-workflows | N | N | N | N |
| docker-workflows | N | N | N | N |
| advanced-targets | N | N | N | N |
| dashboard-visual | N | N | N | N |
| **TOTAL** | **N** | **N** | **N** | **N** |

**Pass rate:** N% (release gate: ≥95%)
**Status:** PASS / FAIL / PARTIAL

## Failure Analysis

### [REGRESSION] test_name (tests/e2e/test_file.py:line)

**Traceback summary:** <one-line description>
**Root cause:** <file>:<line> — <what changed>
**Suggested fix:** <minimal change to restore green>
**Recommend:** `/jmo-ci-debugger` for CI-specific failures

### [FLAKY] test_name

**Pattern matched:** TimeoutExpired
**Action:** Retry; consider @pytest.mark.flaky(reruns=2)

### [ENVIRONMENT] test_name

**Missing:** docker not running / fixture dir absent
**Action:** <specific remediation>

### [TEST-BUG] test_name

**Issue:** Assertion at <file>:<line> incorrect
**Suggested fix:** Update expected value to <value>

## Visual Verification

**Method:** pytest-playwright / agent-browser / skipped

<If playwright ran:>
- test_dashboard_renders: PASS
- test_severity_chart_visible: PASS
- test_findings_table_populated: PASS
- ... etc

<If agent-browser ran:>
- Charts rendered: yes/no (observation)
- Findings table: populated/empty
- Compliance tab: badges visible/missing
- SBOM tree: nodes present/absent
- JS errors: none / <list errors>
- Responsive: mobile OK / tablet OK / desktop OK
- Screenshots: <paths>

## Codebase Delta

**Files changed since main:** N
**Affected test categories:** <list>

## Recommendations

1. [CRITICAL] <regression fix needed>
2. [SUGGESTED] Run `/jmo-test-fabricator` — untested paths found in <modules>
3. [INFO] <flaky test note>
4. [INFO] Release readiness: <pass/fail at ≥95% gate>
```

### Report Output

Write report to: `e2e-verify-report-<YYYYMMDD-HHMMSS>.md`

Also print concise summary to stdout:
```text
E2E Verification: PASS|FAIL (N/N tests, N% pass rate)
Failures: N regression, N flaky, N environment, N test-bug
Visual: PASS|FAIL|skipped
Next: <top recommendation>
```

---

## Skill Connections

| Situation | Recommend |
|-----------|-----------|
| CI-specific job failures | `/jmo-ci-debugger` |
| Untested code paths in delta | `/jmo-test-fabricator` |
| Dashboard rendering broken | `/jmo-dashboard-builder` |
| Ready for release? | `release-readiness` agent |
| New adapter needs e2e coverage | `/jmo-adapter-generator` |
