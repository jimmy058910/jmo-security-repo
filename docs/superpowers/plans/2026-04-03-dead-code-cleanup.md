# Dead Code & Obsolete Files Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove all dead code, obsolete files, stale references, and broken configurations identified by the 6-agent comprehensive audit (2026-04-03).

**Architecture:** Three-phase cleanup: Phase A fixes broken functionality (7 items), Phase B deletes dead code (37 items), Phase C updates stale content (15 items across 30+ files). Each phase produces one atomic commit. Tests run after every phase to verify no regressions.

**Tech Stack:** Python 3.12+, pytest, GitHub Actions YAML, Makefile, Docker

**Scope:** 58 findings across 4 tiers. Test duplication (items 46-47) is deferred to a separate consolidation effort — this plan does not restructure the test suite.

**Tool counts (post Bearer CLI removal v1.0.1):** fast=9, slim=13, balanced=17, deep=28. 27 adapter files (checkov-cicd shares checkov adapter = 28 tools).

---

## Phase A: Fix Broken Functionality (TIER 1)

### Task 1: Fix MCP server path

**Files:**
- Modify: `.claude/mcp.json:5`

- [ ] **Step 1: Fix the path**

In `.claude/mcp.json`, change line 5:

```json
"args": ["run", "mcp", "dev", "scripts/jmo_mcp/jmo_server.py"],
```

The file is currently `server.py` but the actual module is `jmo_server.py`.

- [ ] **Step 2: Verify the file exists**

Run: `ls scripts/jmo_mcp/jmo_server.py`
Expected: file exists

- [ ] **Step 3: Commit**

```bash
git add .claude/mcp.json
git commit -m "fix: correct MCP server path from server.py to jmo_server.py"
```

---

### Task 2: Fix CLI help text tool counts

**Files:**
- Modify: `scripts/cli/jmo.py:1865-1869`

- [ ] **Step 1: Update profile descriptions**

In `scripts/cli/jmo.py`, find the `_add_profile_args` calls around lines 1865-1869 and update:

```python
_add_profile_args(sub, "fast", "Quick scan with 9 best-in-class tools (5-10 min)")
_add_profile_args(
    sub, "balanced", "Balanced scan with 17 production-ready tools (18-25 min)"
)
_add_profile_args(sub, "full", "Comprehensive scan with all 28 tools (40-70 min)")
```

- [ ] **Step 2: Verify the change**

Run: `python -c "from scripts.cli.jmo import main; print('import OK')"`
Expected: `import OK`

- [ ] **Step 3: Commit**

```bash
git add scripts/cli/jmo.py
git commit -m "fix: update CLI help text tool counts (3/8/12 → 9/17/28)"
```

---

### Task 3: Fix DevContainer Python version

**Files:**
- Modify: `.devcontainer/devcontainer.json:3`

- [ ] **Step 1: Update Python image**

In `.devcontainer/devcontainer.json`, change line 3:

```json
"image": "mcr.microsoft.com/devcontainers/python:3.12",
```

- [ ] **Step 2: Commit**

```bash
git add .devcontainer/devcontainer.json
git commit -m "fix: upgrade devcontainer Python 3.11 → 3.12 to match pyproject.toml"
```

---

### Task 4: Fix scheduled.yml slim variant profile bug

**Files:**
- Modify: `.github/workflows/scheduled.yml:988-998`

- [ ] **Step 1: Fix the profile value and tool counts**

In `.github/workflows/scheduled.yml`, find the `validate-variants` matrix around lines 985-998 and update to:

```yaml
          - variant: deep
            expected_tools: 28
            profile: deep
          - variant: balanced
            expected_tools: 17
            profile: balanced
          - variant: slim
            expected_tools: 13
            profile: slim
          - variant: fast
            expected_tools: 9
            profile: fast
```

Key fixes: slim had `profile: fast` (bug), deep had `expected_tools: 28` (verify current), fast had `expected_tools: 8` (now 9).

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/scheduled.yml
git commit -m "fix(ci): correct validate-variants matrix (slim profile, tool counts post Bearer removal)"
```

---

### Task 5: Fix dead Makefile targets

**Files:**
- Modify: `Makefile:38-44,298-330,563-581`

- [ ] **Step 1: Remove `smoke-ai` target and help text**

Delete lines 298-306 (the `smoke-ai` target) and line 38 (the help text for `smoke-ai`).

- [ ] **Step 2: Replace `jmotools` targets with `jmo` equivalents**

Replace lines 308-330 (`setup`, `fast`, `balanced`, `full` targets) with:

```makefile
.PHONY: setup fast balanced full
setup:
	@which jmo >/dev/null 2>&1 || (echo 'Installing package to expose jmo…' && $(PY) -m pip install -e . )
	jmo tools check || true

# Usage: make fast [DIR=~/repos] [TARGETS=results/targets.tsv.txt] [RESULTS=results]
fast:
	@which jmo >/dev/null 2>&1 || (echo 'Installing package to expose jmo…' && $(PY) -m pip install -e . )
	@if [ -n "$(DIR)" ]; then jmo scan --profile fast --repo $(DIR) --results $${RESULTS:-results}; \
	elif [ -n "$(TARGETS)" ]; then jmo scan --profile fast --targets $(TARGETS) --results $${RESULTS:-results}; \
	else echo 'Set DIR=~/repos or TARGETS=results/targets.tsv.txt'; exit 1; fi

balanced:
	@which jmo >/dev/null 2>&1 || (echo 'Installing package to expose jmo…' && $(PY) -m pip install -e . )
	@if [ -n "$(DIR)" ]; then jmo scan --profile balanced --repo $(DIR) --results $${RESULTS:-results}; \
	elif [ -n "$(TARGETS)" ]; then jmo scan --profile balanced --targets $(TARGETS) --results $${RESULTS:-results}; \
	else echo 'Set DIR=~/repos or TARGETS=results/targets.tsv.txt'; exit 1; fi

full:
	@which jmo >/dev/null 2>&1 || (echo 'Installing package to expose jmo…' && $(PY) -m pip install -e . )
	@if [ -n "$(DIR)" ]; then jmo scan --profile deep --repo $(DIR) --results $${RESULTS:-results}; \
	elif [ -n "$(TARGETS)" ]; then jmo scan --profile deep --targets $(TARGETS) --results $${RESULTS:-results}; \
	else echo 'Set DIR=~/repos or TARGETS=results/targets.tsv.txt'; exit 1; fi
```

- [ ] **Step 3: Update help text**

Update lines 41-44 to:

```makefile
	@echo "  setup     - Check security tool installation (jmo tools check)"
	@echo "  fast      - Fast profile scan (9 tools) via jmo"
	@echo "  balanced  - Balanced profile scan (17 tools) via jmo"
	@echo "  full      - Deep profile scan (28 tools) via jmo"
```

- [ ] **Step 4: Fix docker-build-all and docker-build-local**

Replace `docker-build-all` (lines 563-567) with:

```makefile
docker-build-all:
	@echo "Building all Docker image variants..."
	$(MAKE) docker-build VARIANT=full
	$(MAKE) docker-build VARIANT=balanced
	$(MAKE) docker-build VARIANT=slim
	$(MAKE) docker-build VARIANT=fast
```

Replace `docker-build-local` (lines 569-582) with:

```makefile
docker-build-local:
	@echo "Building all Docker variants with 'local' tag for testing..."
	@echo "Target architecture: $(TARGETARCH)"
	docker build --build-arg TARGETARCH=$(TARGETARCH) -f Dockerfile -t jmo-security:local-full .
	docker build --build-arg TARGETARCH=$(TARGETARCH) -f Dockerfile.balanced -t jmo-security:local-balanced .
	docker build --build-arg TARGETARCH=$(TARGETARCH) -f Dockerfile.slim -t jmo-security:local-slim .
	docker build --build-arg TARGETARCH=$(TARGETARCH) -f Dockerfile.fast -t jmo-security:local-fast .
	@echo ""
	@echo "Local Docker images built successfully:"
	@echo "  - jmo-security:local-full"
	@echo "  - jmo-security:local-balanced"
	@echo "  - jmo-security:local-slim"
	@echo "  - jmo-security:local-fast"
	@echo ""
	@echo "Test with: docker run --rm jmo-security:local-full --help"
	@echo "Run E2E tests: DOCKER_IMAGE_BASE=jmo-security DOCKER_TAG=local make test-e2e"
```

- [ ] **Step 5: Commit**

```bash
git add Makefile
git commit -m "fix: replace dead Makefile targets (jmotools→jmo, alpine→current variants, remove smoke-ai)"
```

---

### Task 6: Remove dead finalize-release job

**Files:**
- Modify: `.github/workflows/release.yml:294-325`

- [ ] **Step 1: Delete the dead job**

Delete lines 294-325 (the entire `finalize-release` job and its preceding comment). The job's own comment admits it will never execute.

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "fix(ci): remove dead finalize-release job (never executes per own comment)"
```

---

### Task 7: Remove unused CI env vars

**Files:**
- Modify: `.github/workflows/scheduled.yml:564-565`

- [ ] **Step 1: Remove TEST_URL and RESULTS_BASE**

In the `e2e-ubuntu` job's `run_tests` step env block, delete:

```yaml
          TEST_URL: http://testphp.vulnweb.com
          RESULTS_BASE: /tmp/jmo-e2e-results-${{ github.run_id }}
```

Keep `TEST_REPO` and `TEST_IMAGE` (they are used by tests).

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/scheduled.yml
git commit -m "fix(ci): remove unused TEST_URL/RESULTS_BASE env vars from e2e-ubuntu"
```

---

### Task 8: Run tests to verify Phase A

- [ ] **Step 1: Run full test suite**

Run: `make test-fast`
Expected: all tests pass (no regressions from Phase A changes)

- [ ] **Step 2: Verify Makefile syntax**

Run: `make help`
Expected: help text displays without errors, shows updated target descriptions

---

## Phase B: Delete Dead Code (TIER 2)

### Task 9: Delete dead Python modules and their tests

**Files:**
- Delete: `scripts/core/memory.py`
- Delete: `tests/unit/test_memory.py`
- Delete: `scripts/core/schema_utils.py`
- Delete: `tests/unit/test_schema_utils.py`
- Delete: `tests/schema/test_common_finding_schema.py` (only consumer of schema_utils)
- Delete: `scripts/core/constants.py`
- Delete: `tests/unit/test_constants.py`
- Delete: `scripts/cli/scan_progress.py`
- Delete: `tests/cli/test_scan_progress.py`
- Delete: `scripts/core/generate_dashboard.py`
- Delete: `tests/unit/test_generate_dashboard.py`
- Delete: `scripts/dashboard/create-test-html.py`

- [ ] **Step 1: Delete the dead modules**

```bash
rm scripts/core/memory.py tests/unit/test_memory.py
rm scripts/core/schema_utils.py tests/unit/test_schema_utils.py
rm scripts/core/constants.py tests/unit/test_constants.py
rm scripts/cli/scan_progress.py tests/cli/test_scan_progress.py
rm scripts/core/generate_dashboard.py tests/unit/test_generate_dashboard.py
rm scripts/dashboard/create-test-html.py
```

- [ ] **Step 2: Check test_common_finding_schema.py dependency**

Run: `grep -rn "schema_utils" tests/schema/test_common_finding_schema.py`
If it only imports from `schema_utils`, delete it:

```bash
rm tests/schema/test_common_finding_schema.py
```

If it also tests `schema_validator.py`, keep it and remove only the `schema_utils` imports.

- [ ] **Step 3: Remove stale coverage omit entries from pyproject.toml**

In `pyproject.toml`, remove these lines from BOTH `[tool.coverage.run].omit` and `[tool.coverage.report].omit`:

```text
"scripts/cli/jmotools.py",
```

Also remove from `[tool.coverage.run].omit` only:

```text
"scripts/core/generate_dashboard.py",
```

- [ ] **Step 4: Run tests**

Run: `make test-fast`
Expected: all tests pass (dead module tests are gone, nothing else references them)

- [ ] **Step 5: Commit**

```bash
git add -u
git add pyproject.toml
git commit -m "refactor: remove 6 dead Python modules and their tests

Removed:
- memory.py (zero production callers)
- schema_utils.py (duplicate of schema_validator.py)
- constants.py (only pre-push health check; defines tools with no adapters)
- scan_progress.py (superseded by rich_progress.py)
- generate_dashboard.py (superseded by reporters/ system)
- create-test-html.py (one-shot script)
Also removed jmotools.py from coverage omit (deleted in v0.9.0)"
```

---

### Task 10: Delete legacy shell scripts

**Files:**
- Delete: `scripts/cli/run_audit_and_report.sh`
- Delete: `scripts/cli/security_audit.sh`
- Delete: `scripts/core/run_security_audit.sh`
- Delete: `scripts/core/populate_targets.sh`

- [ ] **Step 1: Delete legacy pre-CLI orchestrators**

```bash
rm scripts/cli/run_audit_and_report.sh
rm scripts/cli/security_audit.sh
rm scripts/core/run_security_audit.sh
rm scripts/core/populate_targets.sh
```

- [ ] **Step 2: Commit**

```bash
git add -u
git commit -m "refactor: remove 4 legacy shell orchestrators (pre-CLI, superseded by jmo)"
```

---

### Task 11: Delete dead dev scripts

**Files:**
- Delete: `scripts/dev/update_adapters_compliance.py`
- Delete: `scripts/dev/fix_test_schema_versions.py`
- Delete: `scripts/dev/verify_react_integration.py`
- Delete: `scripts/dev/test_docker_optimization.sh`
- Delete: `scripts/dev/test_gitlab_manual.sh`
- Delete: `scripts/dev/generate_comprehensive_test_data.py`

- [ ] **Step 1: Delete one-shot migration/verification scripts**

```bash
rm scripts/dev/update_adapters_compliance.py
rm scripts/dev/fix_test_schema_versions.py
rm scripts/dev/verify_react_integration.py
rm scripts/dev/test_docker_optimization.sh
rm scripts/dev/test_gitlab_manual.sh
rm scripts/dev/generate_comprehensive_test_data.py
```

- [ ] **Step 2: Commit**

```bash
git add -u
git commit -m "refactor: remove 6 obsolete dev scripts (one-shot migrations, completed)"
```

---

### Task 12: Delete dead test files

**Files:**
- Delete: `tests/cli/test_wizard_comprehensive_coverage.py.old`
- Delete: `tests/cli/test_wizard_helpers.py.old`
- Delete: `tests/cli/test_wizard_main_and_telemetry.py.old`
- Delete: `tests/unit/test_run_cmd_and_report.py.old`
- Delete: `tests/api/test_csrf_protection.py`
- Delete: `tests/integration/test_docker_trends.sh`
- Delete: `tests/manual/test_visualizations.py`

- [ ] **Step 1: Delete .old files**

```bash
rm tests/cli/test_wizard_comprehensive_coverage.py.old
rm tests/cli/test_wizard_helpers.py.old
rm tests/cli/test_wizard_main_and_telemetry.py.old
rm tests/unit/test_run_cmd_and_report.py.old
```

- [ ] **Step 2: Delete functionally dead test files**

```bash
rm tests/api/test_csrf_protection.py
rm tests/integration/test_docker_trends.sh
rm tests/manual/test_visualizations.py
```

- [ ] **Step 3: Run tests**

Run: `make test-fast`
Expected: all tests pass

- [ ] **Step 4: Commit**

```bash
git add -u
git commit -m "test: remove 7 dead test files (.old backups, no-op CSRF test, unreferenced scripts)"
```

---

### Task 13: Delete unused composite actions

**Files:**
- Delete: `.github/actions/aggregate-coverage/action.yml`
- Delete: `.github/actions/docker-login/action.yml`
- Delete: `.github/actions/install-security-tools/action.yml`
- Delete: `.github/actions/notify-failure/action.yml`
- Delete: `.github/actions/trufflehog-scan/action.yml`

- [ ] **Step 1: Delete unused composite actions**

These were created for a workflow consolidation plan that was never completed. All 5 are completely unused — workflows use inline steps instead. Only `setup-python-jmo` is actually used.

```bash
rm -r .github/actions/aggregate-coverage
rm -r .github/actions/docker-login
rm -r .github/actions/install-security-tools
rm -r .github/actions/notify-failure
rm -r .github/actions/trufflehog-scan
```

- [ ] **Step 2: Commit**

```bash
git add -u
git commit -m "ci: remove 5 unused composite actions (consolidation plan never completed)"
```

---

### Task 14: Remove unused dependencies (scipy, numpy)

**Files:**
- Modify: `pyproject.toml:78-80`
- Modify: `requirements-dev.in:41-42`

- [ ] **Step 1: Remove from pyproject.toml**

In `pyproject.toml`, delete these lines from `[project.optional-dependencies].dev`:

```python
    # Trend analysis (scipy/numpy - upper bounds prevent breaking API changes)
    "scipy>=1.11.0,<1.16.0",
    "numpy>=1.24.0,<2.3.0",
```

- [ ] **Step 2: Remove from requirements-dev.in**

In `requirements-dev.in`, delete these lines:

```text
# Trend Analysis dependencies (Feature #4: Trend Analysis - v1.0.0)
scipy>=1.11.0,<1.15.0  # Mann-Kendall test; constrained for Python 3.10 compatibility
numpy>=1.24.0,<2.3.0  # Explicitly constrain numpy for Python 3.10 support
```

- [ ] **Step 3: Fix stale Ralph Loop comment**

In `requirements-dev.in`, update line 18:

```text
pytest-json-report>=1.5.0  # Machine-readable test output for CI scheduled jobs
```

- [ ] **Step 4: Add missing dev deps to pyproject.toml**

In `pyproject.toml` `[project.optional-dependencies].dev`, add after `"pytest-rerunfailures",`:

```python
    "pytest-xdist>=3.5.0",
    "pytest-json-report>=1.5.0",
```

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml requirements-dev.in
git commit -m "fix(deps): remove unused scipy/numpy (~100MB), sync pytest-xdist/json-report to pyproject.toml"
```

---

### Task 15: Delete orphaned schema and legacy Dockerfile

**Files:**
- Delete: `docs/schemas/policy_metadata.json`
- Delete: `packaging/docker/legacy/Dockerfile.alpine`

- [ ] **Step 1: Delete orphaned files**

```bash
rm docs/schemas/policy_metadata.json
rm packaging/docker/legacy/Dockerfile.alpine
```

Check if `packaging/docker/legacy/` is now empty:

```bash
ls packaging/docker/legacy/
```

If empty, delete the directory:

```bash
rmdir packaging/docker/legacy && rmdir packaging/docker 2>/dev/null; true
```

- [ ] **Step 2: Commit**

```bash
git add -u
git commit -m "refactor: remove orphaned policy_metadata.json schema and legacy Dockerfile.alpine (v0.6.1)"
```

---

### Task 16: Delete orphaned conftest fixtures

**Files:**
- Modify: `tests/conftest.py` (remove `sample_vulnerable_code`, `skip_without_docker`, `mock_subprocess_success`, `mock_subprocess_failure`, `normalize_path`)
- Modify: `tests/performance/conftest.py` (remove `benchmark_context`)
- Modify: `tests/jmo_mcp/conftest.py` (remove `mock_mcp_server`)
- Modify: `tests/e2e/fixtures/conftest.py` (remove `iac_fixtures`, `python_fixtures`, `javascript_fixtures`, `config_fixtures`)

- [ ] **Step 1: Verify fixtures are truly unused before deleting**

Run these greps and only delete fixtures with zero references outside conftest:

```bash
grep -rn "sample_vulnerable_code" tests/ --include="*.py" | grep -v conftest
grep -rn "skip_without_docker" tests/ --include="*.py" | grep -v conftest
grep -rn "mock_subprocess_success" tests/ --include="*.py" | grep -v conftest
grep -rn "mock_subprocess_failure" tests/ --include="*.py" | grep -v conftest
grep -rn "normalize_path" tests/ --include="*.py" | grep -v conftest
grep -rn "benchmark_context" tests/ --include="*.py" | grep -v conftest
grep -rn "mock_mcp_server" tests/ --include="*.py" | grep -v conftest
grep -rn "iac_fixtures\|python_fixtures\|javascript_fixtures\|config_fixtures" tests/ --include="*.py" | grep -v conftest
```

- [ ] **Step 2: Remove confirmed-unused fixtures**

For each fixture that returned zero results in Step 1, delete its definition from the respective conftest.py file.

If `tests/e2e/fixtures/conftest.py` becomes empty (just imports), delete the file entirely.

- [ ] **Step 3: Run tests**

Run: `make test-fast`
Expected: all tests pass

- [ ] **Step 4: Commit**

```bash
git add tests/conftest.py tests/performance/conftest.py tests/jmo_mcp/conftest.py tests/e2e/fixtures/conftest.py
git commit -m "test: remove 11 orphaned conftest fixtures (never used by any test)"
```

---

### Task 17: Run full test suite after Phase B

- [ ] **Step 1: Run tests with coverage**

Run: `make test-parallel`
Expected: all tests pass, coverage ≥85%

- [ ] **Step 2: Verify no broken imports**

Run: `python -c "import scripts.cli.jmo; import scripts.core.normalize_and_report; print('OK')"`
Expected: `OK`

---

## Phase C: Update Stale Content (TIER 3)

### Task 18: Update agent files (11 adapters → 27+, v0.6.1 → v1.0.0)

**Files:**
- Modify: `.claude/agents/codebase-explorer.md`
- Modify: `.claude/agents/code-quality-auditor.md`
- Modify: `.claude/agents/coverage-gap-finder.md`
- Modify: `.claude/agents/dependency-analyzer.md`
- Modify: `.claude/agents/security-auditor.md`
- Modify: `.claude/agents/release-readiness.md`
- Modify: `.claude/agents/doc-sync-checker.md`

- [ ] **Step 1: In ALL agent files, do these replacements**

For each `.claude/agents/*.md` file:

1. Replace all occurrences of `v0.6.1` with `v1.0.0`
2. Replace `11 adapters` with `27 adapters` (and similar patterns like `11 adapter`, `8/11`, `7/11`)
3. Replace `jmotools` with `jmo` (for CLI command references)
4. Replace `jmotools.py` with `jmo.py` (for file path references)
5. Remove references to `SAMPLE_OUTPUTS.md` — replace with `docs/RESULTS_GUIDE.md`
6. Remove references to `WIZARD_IMPLEMENTATION.md` — replace with `docs/CLI_REFERENCE.md`

- [ ] **Step 2: Fix code-quality-auditor.md specifically**

Remove or mark as COMPLETED the CRITICAL-002 and CRITICAL-003 sections that recommend creating `scan_orchestrator.py` (it already exists).

- [ ] **Step 3: Fix release-readiness.md Docker variants**

Replace `full/slim/alpine` with `full/balanced/slim/fast`.

- [ ] **Step 4: Fix coverage-gap-finder.md metrics**

Update `253+ tests` to `8,000+ tests`, `91% coverage` to `87% coverage`.

- [ ] **Step 5: Fix dependency-analyzer.md jmotools references**

Remove all line-specific references to `jmotools.py:28`, `jmotools.py:78`, `jmotools.py:112`, `jmotools.py:145`.

- [ ] **Step 6: Commit**

```bash
git add .claude/agents/
git commit -m "docs: update all agent files (v0.6.1→v1.0.0, 11→27 adapters, jmotools→jmo)"
```

---

### Task 19: Update skill files

**Files:**
- Modify: `.claude/skills/jmo-dashboard-builder/SKILL.md`
- Modify: `.claude/skills/jmo-dashboard-builder/references/troubleshooting.md`
- Modify: `.claude/skills/jmo-skill-optimizer/SKILL.md`
- Modify: `.claude/skills/jmo-skill-optimizer/references/automated-audit-details.md`
- Modify: `.claude/skills/content-generator/SKILL.md`
- Modify: `.claude/skills/jmo-documentation-updater/SKILL.md`
- Modify: `.claude/skills/jmo-documentation-updater/templates/doc-update-templates.md`
- Modify: `.claude/skills/community-manager/launch-coordination.md`
- Delete: `.claude/screenshot-best-practices.md`

- [ ] **Step 1: Fix jmo-dashboard-builder skill paths**

In `SKILL.md`, update all references:
- `dashboard/` → `scripts/dashboard/`
- `html_reporter_react.py` → `html_reporter.py` (in `scripts/core/reporters/`)
- `jmo.yml -> outputs.html.use_react_dashboard` → remove (config flag doesn't exist; the React dashboard is built via `npm run build` in `scripts/dashboard/`)

In `references/troubleshooting.md`, update paths similarly.

- [ ] **Step 2: Fix jmo-skill-optimizer references to nonexistent files**

In `SKILL.md`, remove references to:
- `SKILL_WORKFLOWS.md` (doesn't exist)
- `scripts/dev/audit_skills.py` (doesn't exist)
- `.jmo/memory/skills/audit-YYYYMMDD.json` (directory doesn't exist)

In `references/automated-audit-details.md`, similarly remove or replace with working alternatives.

- [ ] **Step 3: Fix content-generator skill**

In `SKILL.md`:
- Replace `11+ security scanners` with `27+ security scanners`
- Replace `3 Docker variants (full, slim, alpine)` with `4 Docker variants (fast, slim, balanced, deep)`

- [ ] **Step 4: Fix jmo-documentation-updater**

In `SKILL.md` and `templates/doc-update-templates.md`:
- Remove references to `SAMPLE_OUTPUTS.md` and `WIZARD_IMPLEMENTATION.md`

- [ ] **Step 5: Fix community-manager launch posts**

In `launch-coordination.md`: remove references to `linkedin-launch-post.md` and `devto-launch-post.md` (files deleted).

Replace all `jmotools` CLI references with `jmo` in: `hashnode-launch-post.md`, `reddit-post-opensource.md`, `reddit-post-python.md`, `reddit-strategy.md`.

- [ ] **Step 6: Delete screenshot-best-practices.md**

```bash
rm .claude/screenshot-best-practices.md
```

References `test-dashboards-playwright.js` and `generate_test_dashboards.py` which are both deleted/archived.

- [ ] **Step 7: Commit**

```bash
git add .claude/skills/ .claude/screenshot-best-practices.md
git commit -m "docs: update skill files (fix paths, remove dead references, update tool counts)"
```

---

### Task 20: Fix tool count inconsistencies across docs

**Files:**
- Modify: `docs/QUICK_REFERENCE.md`
- Modify: `docs/USER_GUIDE.md`
- Modify: `docs/USAGE_MATRIX.md`
- Modify: `docs/examples/wizard-examples.md`
- Modify: `docs/examples/scan_from_tsv.md`
- Modify: `docs/internal/TESTING_MATRIX.md`
- Modify: `docs/internal/MANUAL_TESTING_CHECKLIST.md`
- Modify: `docs/internal/screenshots/README.md`
- Modify: `DOCKER_HUB_README.md`
- Modify: `SECURITY.md`
- Modify: `CHANGELOG.md`
- Modify: `samples/README.md`
- Modify: `Dockerfile:423,434` (footer comments)

- [ ] **Step 1: Fix tool counts across docs**

Correct tool counts everywhere to match post-Bearer-removal canonical values (fast=9, slim=13, balanced=17, deep=28, 27 adapters). Grep and fix each:

```bash
grep -rn "28 tools\|29 tools" docs/ DOCKER_HUB_README.md SECURITY.md CHANGELOG.md samples/README.md
grep -rn "18 tools" docs/ DOCKER_HUB_README.md SECURITY.md CHANGELOG.md samples/README.md
grep -rn "14 tools" docs/ DOCKER_HUB_README.md SECURITY.md CHANGELOG.md samples/README.md
grep -rn "8 tools" docs/ DOCKER_HUB_README.md SECURITY.md CHANGELOG.md samples/README.md | grep -i fast
```

For deep profile: use `28 tools`. For balanced: `17 tools`. For slim: `13 tools`. For fast: `9 tools`.

- [ ] **Step 2: Fix Python version references**

In `docs/examples/scan_from_tsv.md`: change `Python 3.9+` to `Python 3.12+`
In `docs/internal/screenshots/README.md`: change `Python 3.8+` to `Python 3.12+`

- [ ] **Step 3: Fix test count**

In `docs/internal/MANUAL_TESTING_CHECKLIST.md`: change `5,000+ tests` to `8,000+ tests`

- [ ] **Step 4: Fix Dockerfile footer comments**

In `Dockerfile`, update lines ~423 and ~434:
- Replace `27 tools` / `12 → 27 tools` with `28 tools (27 Docker-ready + OPA policy engine)`

- [ ] **Step 5: Commit**

```bash
git add docs/ DOCKER_HUB_README.md SECURITY.md CHANGELOG.md samples/README.md Dockerfile
git commit -m "docs: fix tool counts across docs (post Bearer removal: 9/13/17/28), Python version refs"
```

---

### Task 21: Clean up completed plans

**Files:**
- Modify: `docs/superpowers/plans/2026-03-12-e2e-consolidation.md`
- Modify: `docs/superpowers/plans/2026-03-24-pr-review-fixes.md`
- Modify: `docs/superpowers/plans/2026-03-12-claude-directory-cleanup.md`

- [ ] **Step 1: Add completion note to each plan**

At the top of each plan file (after the header), add:

```markdown
> **STATUS: COMPLETED** — This plan was fully executed. Retained for historical reference.
```

This is preferable to deleting them since they serve as architectural decision records.

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/plans/
git commit -m "docs: mark 3 completed plans as COMPLETED (historical reference)"
```

---

### Task 22: Fix scripts/dev/README.md duplicate content

**Files:**
- Modify: `scripts/dev/README.md`

- [ ] **Step 1: Check and fix duplicate content**

Read the file and remove the duplicated sections (the entire content appears to be rendered twice).

- [ ] **Step 2: Also update to remove references to deleted scripts**

Remove entries for the 6 dev scripts deleted in Task 11.

- [ ] **Step 3: Commit**

```bash
git add scripts/dev/README.md
git commit -m "docs: fix scripts/dev/README.md (remove duplicate content, update for deleted scripts)"
```

---

### Task 23: Final verification

- [ ] **Step 1: Run full test suite**

Run: `make test-fast`
Expected: all tests pass

- [ ] **Step 2: Run linting**

Run: `make lint`
Expected: no lint errors

- [ ] **Step 3: Run formatting**

Run: `make fmt`
Expected: no formatting changes (or auto-fixed)

- [ ] **Step 4: Verify import health**

Run: `python -c "import scripts.cli.jmo; import scripts.core.normalize_and_report; import scripts.core.plugin_loader; print('All imports OK')"`
Expected: `All imports OK`

- [ ] **Step 5: Check git status**

Run: `git status`
Expected: clean working tree (all changes committed)

- [ ] **Step 6: Review commit log**

Run: `git log --oneline -20`
Expected: all commits follow conventional commit format

---

## Deferred Items (Not in Scope)

These items were identified during the audit but require separate analysis/approval:

1. **Test duplication (scan_jobs/ vs cli/)** — 7 duplicate test file pairs need careful consolidation to avoid coverage loss
2. **Triplicate wizard tests** — ~16 files across unit/, wizard_flows/, cli/ test the same modules; needs a test architecture decision
3. **UNICODE_FALLBACKS duplication** — 4 CLI command files duplicate the same dict; minor code smell
4. **`__version__` in 4 files** — deliberate pattern, not dead code
5. **Dead methods in plugin_loader.py** — `reload_plugin()`, `unregister()`, `list_all_available()` are test-only; low risk but removing them would break their tests without benefit
6. **`osv-scanner` in TOOL_SCAN_TYPES** — needs decision: add an adapter or remove the entry
7. **Ghost tool references (gitleaks, tfsec)** — in `compliance_mapper.py` and `rule_equivalence.py`; needs analysis of whether these are forward-looking placeholders or truly dead

---

## Summary

| Phase | Tasks | Commits | Risk |
|-------|-------|---------|------|
| A: Fix Broken | 8 | 7 | LOW (fixes bugs) |
| B: Delete Dead | 9 | 8 | LOW (pure deletions) |
| C: Update Stale | 6 | 5 | VERY LOW (docs/comments only) |
| **Total** | **23** | **20** | |
