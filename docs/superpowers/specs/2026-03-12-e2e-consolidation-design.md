# E2E Infrastructure Consolidation & AI-Driven Verification

**Date:** 2026-03-12
**Status:** Approved
**Scope:** CI workflows, e2e tests, visual testing, Claude skill

## Summary

Consolidate JMo Security's fragmented e2e/CI infrastructure (8 workflows, 772-line bash script, duplicate test files) into a unified, pytest-native system with AI-driven orchestration and browser-based dashboard verification.

**Motivation:** Testing infrastructure grew organically across multiple languages (bash + Python), multiple workflow files (8), and multiple test directories with overlap (180+ test functions across e2e/ and integration/ directories, some duplicated). This consolidation reduces maintenance burden, eliminates duplication, and adds capabilities that didn't exist before (visual dashboard testing, AI-driven failure analysis).

**Note:** E2E tests do not affect the 85% coverage threshold. Coverage is measured with `--cov=scripts` which only instruments the `scripts/` package, not the `tests/` directory.

**Inspired by:** [coleam00/link-in-bio-page-builder commit 96471d2](https://github.com/coleam00/link-in-bio-page-builder/commit/96471d28642a4d4d973b9c4cfa2bac7bad39bf02) — E2E Testing Skill with Browser Automation pattern.

## Design Sections

### 1. Workflow Consolidation (8 to 4)

#### 1.1 Composite Actions

Three composite actions already exist:
- `setup-python-jmo/action.yml` -- Python setup with caching (NOTE: defaults to 3.11, must bump to 3.12)
- `install-security-tools/action.yml` -- Tool installation by profile
- `aggregate-coverage/action.yml` -- Coverage XML merging

Update existing + create new composite actions:

```text
.github/actions/
  setup-python-jmo/action.yml      # EXISTING: bump default from 3.11 to 3.12
  install-security-tools/action.yml # EXISTING: keep as-is
  aggregate-coverage/action.yml     # EXISTING: keep as-is
  docker-login/action.yml           # NEW: multi-registry login (GHCR + Docker Hub + ECR)
  trufflehog-scan/action.yml        # NEW: TruffleHog filesystem scan + verified-only check
  notify-failure/action.yml         # NEW: create/update GitHub issue on job failure
```

#### 1.2 Consolidated Workflows

**`ci.yml`** -- Fast feedback on every push/PR

| Job | Source | Change |
|-----|--------|--------|
| quick-checks | ci.yml | Unchanged |
| test-sharded | ci.yml test-matrix + test-sharded | Expand to all 3 OS; eliminates test-matrix duplicate |
| coverage-aggregate | ci.yml | Unchanged |
| lint-quick | ci.yml | Unchanged (PR/push only) |

Removed from ci.yml: `lint-full` (moved to scheduled.yml), `integration-tests` (moved to scheduled.yml), `test-matrix` (eliminated -- absorbed by test-sharded).

**`scheduled.yml`** -- All periodic testing (rename `scheduled-tests.yml` to `scheduled.yml`, absorb `docker-validation.yml`)

Nightly (2 AM UTC daily):
- nightly-extended-tests
- nightly-cross-platform
- nightly-security-regression
- nightly-docker-smoke (add timeout-minutes: 30 -- currently missing)
- tool-smoke-tests
- nightly-notify-failure
- lint-full (moved from ci.yml)
- integration-tests (moved from ci.yml)

E2E (4 AM UTC weekdays):
- e2e-ubuntu
- e2e-macos
- e2e-tool-integration
- tool-contract-tests
- e2e-visual (NEW -- pytest-playwright dashboard tests)
- e2e-summary

Weekly (3 AM UTC Sunday):
- docker-validate-variants (absorbed from docker-validation.yml)
- docker-validation-summary

Manual dispatch only:
- performance-benchmarks

**`release.yml`** -- Everything release-related (absorbs `automated-release.yml`)

Two entry points in one file:
- `workflow_dispatch` triggers: prepare-release, finalize-release (from automated-release.yml)
- `push: tags: v*` triggers: pre-release-check, pypi-publish, docker-build, docker-size-benchmark, docker-scan, docker-hub-readme, verify-badges, homebrew-bump, winget-bump

**`maintenance.yml`** -- Weekly housekeeping (absorbs `weekly-tool-update.yml` + `version-check.yml`)

- auto-update-tools (Sunday 00:00 UTC)
- check-versions (Sunday 02:00 UTC, `needs: auto-update-tools`)
- check-dockerfile-consistency (Sunday 02:00 UTC)
- check-python-deps (Sunday 02:00 UTC)
- version-check-summary
- repo-completeness (Monday 06:00 UTC)

Key improvement: tool-update to version-check dependency becomes explicit via `needs:` instead of implicit cron timing.

#### 1.3 Bug Fixes in Consolidation

- Add `timeout-minutes: 30` to nightly-docker-smoke (currently inherits 360-min default)
- Review coverage aggregation merge logic (currently uses `max(existing, new)` for hit counts -- verify this correctly handles branch coverage attributes, not just line hits)
- Use job-start timestamp for nightly notification issue titles (prevents midnight race condition)
- Eliminate test-matrix job (duplicates test-sharded on Ubuntu/3.12)

### 2. E2E Test Migration (Bash to Pytest)

#### 2.1 Problem

- `run_comprehensive_tests.sh` is 772 lines of bash -- different language from rest of codebase
- `tests/integration/test_docker_variants.py` (464 lines, tests 3 variants: full/slim/alpine) significantly overlaps with `tests/e2e/test_docker_variants.py` (698 lines, tests 4 variants: deep/balanced/slim/fast). Different structure but same test categories (tool availability, scan capability, help/version commands). Must be merged, not simply deleted.
- 25 bash tests (U1-U12, M1-M6, W1-W4, A1-A3) overlap with existing pytest e2e files
- Report generation locked to bash CSV format

#### 2.2 New Test Structure

```text
tests/e2e/
  conftest.py                    # NEW: shared fixtures (jmo_runner, scan_results, fixture setup)
  test_scan_workflows.py         # NEW: replaces U1-U6, M1-M3, W1 (parametrized)
  test_docker_workflows.py       # RENAMED + EXPANDED: absorbs U9-U11, M5-M6, W3-W4
  test_wizard_workflows.py       # NEW: replaces M4, W2
  test_ci_gating.py              # NEW: replaces U12
  test_advanced_targets.py       # NEW: replaces A1-A3
  test_real_tool_scans.py        # Keep (real tool CVE detection)
  test_cross_platform.py         # Keep (path normalization, full workflow)
  test_security_hardening.py     # Keep (SQL injection, path traversal prevention)
  test_windows_specific.py       # Keep
  test_linux_specific.py         # Keep
  test_macos_specific.py         # Keep
  test_dashboard_visual.py       # NEW: pytest-playwright dashboard tests
  fixtures/
    conftest.py                  # NEW: fixture data loaders (session-scoped, imported by tests/e2e/conftest.py)
    iac/                         # Keep
    python/                      # Keep
    javascript/                  # Keep
    configs/                     # Keep
```

Fixture conftest roles:
- `tests/e2e/conftest.py` -- shared fixtures (`jmo_runner`, `scan_results`), pytest hooks (report generation, release readiness check)
- `tests/e2e/fixtures/conftest.py` -- session-scoped fixture data loaders (IaC files, vulnerable apps, configs); imported by `tests/e2e/conftest.py`

Files deleted:
- `tests/e2e/run_comprehensive_tests.sh` (772 lines, replaced by pytest)
- `tests/e2e/generate_report.py` (replaced by pytest-json-report + conftest hook)
- `tests/e2e/fixtures/setup_fixtures.sh` (replaced by pytest fixtures)

Files merged:
- `tests/integration/test_docker_variants.py` (464 lines) merged into `tests/e2e/test_docker_workflows.py` -- combine 3-variant (full/slim/alpine) and 4-variant (deep/balanced/slim/fast) coverage into single parametrized file, then delete integration version

#### 2.3 Parametrized Test Pattern

Bash tests U1-U6, M1-M3, W1 become a single parametrized pytest function:

```python
SCAN_WORKFLOWS = [
    pytest.param(
        "U1", "Single repo native CLI",
        ["ci", "--repo", FIXTURES["repo"], "--profile", "balanced", "--allow-missing-tools"],
        validate_basic_scan, "linux",
        id="U1-repo-native",
    ),
    pytest.param(
        "U2", "Single image native CLI",
        ["ci", "--image", FIXTURES["image"], "--tools", "trivy,syft", "--allow-missing-tools"],
        validate_basic_scan, "linux",
        marks=[pytest.mark.skipif(not shutil.which("docker"), reason="Docker required")],
        id="U2-image-native",
    ),
    # ... etc
]

@pytest.mark.e2e
@pytest.mark.slow
@pytest.mark.parametrize("test_id,desc,args,validator,platform", SCAN_WORKFLOWS)
def test_scan_workflow(test_id, desc, args, validator, platform, jmo_runner):
    if platform != current_platform():
        pytest.skip(f"Test {test_id} is for {platform}")
    rc, stdout, stderr, results_dir = jmo_runner(args)
    validator(results_dir)
```

Test IDs (U1, U2, etc.) preserved for continuity with existing documentation and CI reporting.

All subprocess invocations in e2e fixtures and test code MUST use `shell=False` per project security policy (CLAUDE.md).

#### 2.4 Report Generation Replacement

| Current | Replacement |
|---------|-------------|
| Bash CSV output | `pytest --json-report --json-report-file=e2e-results.json` |
| `generate_report.py` (CSV to markdown) | `conftest.py` pytest hook generating markdown from JSON |
| Console color-coded summary | pytest `-v` output + `pytest-sugar` |
| Release readiness indicator | Custom conftest hook checking pass rate >= 95% |

#### 2.5 Makefile Targets

| Target | Command |
|--------|---------|
| `make test-e2e` | `pytest tests/e2e/ -m "e2e" --timeout=900` |
| `make test-e2e-visual` | `pytest tests/e2e/test_dashboard_visual.py` |
| `make test-e2e-report` | Generates markdown report from JSON output |

### 3. Visual Testing Layer

#### 3.1 Two Tools, Two Purposes

| | pytest-playwright | agent-browser |
|---|---|---|
| Where | CI (all platforms) + local | Claude skill (WSL/Linux/macOS) |
| Purpose | Deterministic: "has this changed?" | AI reasoning: "does this look right?" |
| Trigger | `pytest tests/e2e/test_dashboard_visual.py` | `/jmo-e2e-verify` skill |
| Windows | Native (battle-tested) | WSL only (native Windows broken) |
| Dependency | `pip install pytest-playwright` (~150MB Chromium) | `npm install -g agent-browser` |

#### 3.2 pytest-playwright Dashboard Tests

File: `tests/e2e/test_dashboard_visual.py`

Tests:
- `test_dashboard_renders` -- loads without JS errors
- `test_severity_chart_visible` -- chart has non-zero dimensions
- `test_findings_table_populated` -- table rows >= 1
- `test_severity_filter_works` -- clicking filter reduces row count
- `test_compliance_tab_renders` -- framework badges visible
- `test_sbom_tree_renders` -- tree nodes exist
- `test_responsive_mobile` -- 375x812, no horizontal overflow
- `test_responsive_tablet` -- 768x1024, layout shift verified
- `test_responsive_desktop` -- 1440x900, full layout visible
- `test_diff_report_renders` -- new/fixed/unchanged sections
- `test_copy_to_clipboard` -- copy button works
- `test_dark_mode_toggle` -- CSS class change on toggle
- `test_screenshot_baseline` -- visual regression via `to_have_screenshot()`

Dependency: optional `[visual]` extra in pyproject.toml.

```toml
# Add to [project.optional-dependencies]
visual = ["pytest-playwright>=0.5.0"]

# Add to dev dependencies (requirements-dev.in)
# pytest-json-report  # E2E report generation
```

Screenshot baselines stored in `tests/e2e/test_dashboard_visual-snapshots/`.

#### 3.3 agent-browser for Claude Skill

Environment detection: agent-browser available? -> WSL fallback? -> Docker fallback? -> skip browser verification.

Claude uses agent-browser interactively (not scripted) to open dashboard.html, navigate tabs, check rendering, capture screenshots, and report observations in natural language.

Requires `--allow-file-access` flag for file:// URLs.

### 4. Claude Skill: `/jmo-e2e-verify`

#### 4.1 Skill Metadata

```yaml
name: jmo-e2e-verify
description: >
  AI-orchestrated e2e verification with parallel sub-agents,
  intelligent failure analysis, and visual dashboard inspection.
user-invocable: true
context: fork
allowed-tools: Read, Write, Edit, Glob, Grep, Bash, Agent, TaskCreate, TaskUpdate
argument-hint: "[scope] - quick|full|visual|scan-only (default: quick)"
```

#### 4.2 Six Phases

**Phase 1 -- Pre-flight (~30s):** Environment detection, tool checks, scope determination from `$ARGUMENTS`.

**Phase 2 -- Parallel Research (3 concurrent sub-agents):**
- Codebase Delta Agent: `git diff main...HEAD`, maps changes to affected test categories
- Test Health Agent: recent CI results, flaky test history, open bug/test-failure issues
- Infrastructure Agent: Docker availability, tool versions, disk space, fixture status

**Phase 3 -- Test Execution:** Run pytest e2e suite with task tracking per test category. Skip irrelevant categories based on Phase 2 research.

**Phase 4 -- Failure Analysis:** For each failure, read test code + source code + traceback. Cross-reference with known flaky list. Categorize as: known flaky, infrastructure, real regression, or test bug. Provide fix suggestions with file:line references.

**Phase 5 -- Visual Verification (if agent-browser available):** Open dashboard.html, navigate tabs, check charts/tables/SBOM tree, test responsive viewports, capture screenshots, check for JS console errors.

**Phase 6 -- Report:** Unified summary with test results, visual inspection findings, and actionable recommendations.

#### 4.3 Scope Modes

| Mode | What Runs | Duration |
|------|-----------|----------|
| `quick` (default) | Scan workflows + CI gating + visual spot-check | ~5 min |
| `full` | All e2e tests + full visual suite + Docker workflows | ~30-60 min |
| `visual` | Dashboard visual tests only | ~3 min |
| `scan-only` | Run scan + report against fixtures, no assertions | ~2 min |

#### 4.4 Skill Connections

- Recommends `/jmo-ci-debugger` for CI-specific failures
- Recommends `/jmo-test-fabricator` for untested code paths
- Recommends `/jmo-dashboard-builder` for dashboard rendering issues
- Feeds report into `release-readiness` agent for release verification

### 5. Migration Strategy (Phased Rollout)

#### Phase 1 -- Foundation (no behavior change)

1. Update `setup-python-jmo` default from 3.11 to 3.12; create 3 new composite actions (`docker-login`, `trufflehog-scan`, `notify-failure`)
2. Merge `tests/integration/test_docker_variants.py` into `tests/e2e/test_docker_workflows.py`, then delete integration version
3. Add `pytest-playwright` to `[visual]` optional deps, `pytest-json-report` to dev deps (requirements-dev.in)
4. Create `tests/e2e/conftest.py` with shared e2e fixtures

Validation: `make test` passes, all 8 workflows still work.

#### Phase 2 -- Test Migration (medium risk)

1. Create new pytest e2e files alongside bash script (additive)
2. Run parity verification: both bash and pytest in CI, compare results
3. Add `make test-e2e` target
4. After parity confirmed, delete bash script, generate_report.py, setup_fixtures.sh

Critical gate: Step 2.7 parity verification must pass for one full nightly cycle.

#### Phase 3 -- Workflow Consolidation (medium-high risk)

Order: safest first.
1. Merge maintenance workflows (3 to 1) -- weekly, low blast radius
2. Migrate all workflows to use composite actions
3. Merge automated-release.yml into release.yml
4. Move lint-full + integration-tests from ci.yml to scheduled.yml
5. Absorb docker-validation.yml into scheduled.yml
6. Expand test-sharded to all 3 OS, delete test-matrix
7. Delete old workflow files
8. Update scheduled.yml e2e jobs to call pytest

#### Phase 4 -- Skill & Browser Layer (low risk, independent)

1. Create `.claude/skills/jmo-e2e-verify/SKILL.md`
2. Create `tests/e2e/test_dashboard_visual.py`
3. Generate screenshot baselines
4. Add `e2e-visual` job to scheduled.yml
5. Test agent-browser integration in WSL

Can start as soon as Phase 1 complete -- independent of Phases 2-3.

#### Phase 5 -- Cleanup & Documentation

1. Update CLAUDE.md, TEST.md, tests/e2e/README.md
2. Update .claude/skills/INDEX.md, AGENTS.md
3. Run release-readiness agent for final validation

#### Rollback Plan

| Phase | Rollback |
|-------|----------|
| Phase 1 | Delete composite actions, restore duplicate file |
| Phase 2 | Bash script exists until explicit delete step |
| Phase 3 | Git revert workflow merge commit |
| Phase 4 | Delete skill file, no existing behavior affected |

Every phase independently revertible.

#### Dependency Graph

```text
Phase 1 --> Phase 2 --> Phase 3.8

Phase 1 --> Phase 3.1-3.7 (can start after Phase 1, but must coordinate
                           with Phase 2 to avoid editing same workflow
                           files simultaneously)

Phase 1 --> Phase 4 (independent of Phases 2-3)

Phase 2 + Phase 3 + Phase 4 --> Phase 5
```

## Research Findings

### Workflow Overlaps Discovered

- Unit tests run twice: test-matrix + test-sharded on Ubuntu/3.12
- Docker testing in 3 places across 2 workflows
- TruffleHog scanning in 2 workflows (ci.yml + scheduled-tests.yml)
- Integration tests with real tools in 2 workflows

### agent-browser Platform Status

- Linux/macOS: fully functional
- Windows: broken (GitHub issues #549, #262, #90, #25, #208, #56)
- WSL: works (Linux binary)
- Headless: supported (no display required)
- file:// URLs: supported with `--allow-file-access`

### pytest-playwright Platform Status

- All platforms: fully functional, battle-tested
- Headless: default mode, no display required
- file:// URLs: native support via `page.goto()`
- CI: works in all GitHub Actions runners without X server
- Weight: pip package 16.9 kB, Chromium ~150 MB

## Out of Scope

- Video recording of test runs (screenshots sufficient)
- Cross-browser testing (Chromium only)
- Network interception/mocking (dashboard is local file)
- Auth/cookie management (dashboard has no auth)
- Performance profiling / Lighthouse (deferred)
- Modifying code to fix failures (skill reports, doesn't fix)
- Replacing CI (skill is on-demand, CI is automatic)
