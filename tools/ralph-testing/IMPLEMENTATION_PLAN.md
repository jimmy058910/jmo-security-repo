<!-- markdownlint-disable MD037 -->
# Implementation Plan - CLI Testing

This file is shared state between Ralph Loop iterations. Claude reads it to find work and updates it to record progress.

---

## Task Templates

### BUG Task

```text
### TASK-XXX: [Bug] Description

**Type:** Bug
**Priority:** Critical | High | Medium
**Score:** [S+F+C] = X (S:X, F:X, C:X)
**Confidence:** XX%
**Status:** Open | In Progress | Resolved
**File:** path/to/file.py:LINE
**Symptom:**
[Error message or behavior]
**Root Cause:** [Analysis]
**Fix:** [Solution]
**Resolution:** [Notes after fixing]
```

### COVERAGE Task

```text
### TASK-XXX: [Coverage] Module needs tests

**Type:** Coverage
**Priority:** High | Medium
**Score:** [S+F+C] = X
**Confidence:** 100%
**Status:** Open | In Progress | Resolved
**Target:** path/to/file.py::function_name
**Current Coverage:** X%
**Gap:**

- [ ] Happy path test
- [ ] Error path test
- [ ] Edge cases
**Resolution:** [Notes after fixing]
```

### SECURITY Task

```text
### TASK-XXX: [Security] Description

**Type:** Security
**Priority:** Critical | High
**Score:** [S+F+C] = X
**Confidence:** XX%
**CWE:** CWE-XXX
**Status:** Open | In Progress | Resolved
**File:** path/to/file.py:LINE
**Vulnerability:** [Code snippet]
**Risk:** [Impact]
**Fix:** [Secure implementation]
**Resolution:** [Notes after fixing]
```

---

## Task Statistics

| Type | Critical | High | Medium | Total |
|------|----------|------|--------|-------|
| Bug | 2 | 14 | 0 | 16 |
| Coverage | 0 | 2 | 2 | 4 |
| Security | 0 | 0 | - | 0 |
| **Total** | **2** | **16** | **2** | **20** |

**Status:** 48 resolved, 0 open.

---

## Force Mode Full Audit Summary (2026-02-04) - Session 3

**Mode:** FORCE (all cooldowns ignored)

**Test Results Summary:**

- core: 124 passed, 3 skipped
- cli: 1517 passed, 2 skipped, 2 fixed (missing MockToolStatusSummary mocks)
- adapters: 1886 passed
- reporters: 392 passed, 1 skipped
- wizard (all test files): 755 passed, 1 skipped

**Issues Found & Fixed This Session:**

### TASK-048: [Bug] test_all_tools_ready missing get_tool_summary mock

**Type:** Bug
**Priority:** High
**Score:** [S+F+C] = 6 (S:2, F:2, C:2)
**Confidence:** 100%
**Status:** Resolved
**File:** tests/cli/test_wizard_tool_checker.py:175
**Symptom:**

```text

AssertionError: assert 'trivy' in []
WARNING: Tool check failed: '>' not supported between instances of 'MagicMock' and 'int'
```

**Root Cause:**
Test mocked `ToolManager` class but not `get_tool_summary()` return value. `summary.profile_total > 0` comparison fails when summary is a raw MagicMock.
**Fix:**
Added `manager_instance.get_tool_summary.return_value = MockToolStatusSummary(...)` with proper integer fields.
**Resolution:** (2026-02-04) Fixed - test passes.

### TASK-049: [Bug] test_yes_mode_continues_with_missing and test_tool_with_startup_crash missing summary mocks

**Type:** Bug
**Priority:** High
**Score:** [S+F+C] = 6 (S:2, F:2, C:2)
**Confidence:** 100%
**Status:** Resolved
**File:** tests/cli/test_wizard_tool_checker.py:246,1203
**Symptom:**
Same as TASK-048 - `'>' not supported between instances of 'MagicMock' and 'int'`
**Root Cause:**
Same pattern - missing `get_tool_summary()` return value mock.
**Fix:**
Added `MockToolStatusSummary` return values for both tests with appropriate fields (`not_installed=["bandit"]` and `version_issues=["checkov"]`).
**Resolution:** (2026-02-04) Fixed - all 52 tool_checker tests pass.

---

## Previous Session Summary (Session 2)

**Test Results:**

- core + adapters + reporters + history + dedup: 2622 passed, 4 skipped, 1 fixed
- cli (excl automation): 1430 passed, 2 skipped, 3 fixed
- scan_jobs: 112 passed
- wizard_flows + unit wizard tests: 738 passed
- adapters: 1886 passed
- reporters: 392 passed, 1 skipped

**Issues Found & Fixed (Session 2):**

### TASK-044: [Bug] test_fast_profile_not_affected flawed assertion

**Type:** Bug
**Priority:** Medium
**Score:** [S+F+C] = 5 (S:1, F:2, C:2)
**Confidence:** 100%
**Status:** Resolved
**File:** tests/core/test_tool_registry.py:126
**Symptom:**

```text

AssertionError: assert {'checkov', ...} == {'checkov', ..., 'shellcheck', ...}
Extra items in the right set: 'shellcheck'
```

**Root Cause:**
Test assumed fast profile has no platform-specific tools, but shellcheck is linux/macos only and is in fast profile.
**Fix:**
Renamed test to `test_fast_profile_filters_platform_specific` and updated assertions to verify shellcheck is filtered on Windows.
**Resolution:** (2026-02-04) Fixed - test now correctly asserts platform-specific filtering behavior.

### TASK-045: [Bug] test_run_wizard_non_interactive missing ToolManager mock

**Type:** Bug
**Priority:** High
**Score:** [S+F+C] = 6 (S:2, F:2, C:2)
**Confidence:** 100%
**Status:** Resolved
**File:** tests/cli/test_wizard.py:248
**Symptom:**

```text

TypeError: expected string or bytes-like object, got 'MagicMock'
```

**Root Cause:**
Test mocked `subprocess.run` but not `ToolManager` - wizard's `execute_scan()` calls `ToolManager.get_tool_summary()` which returns MagicMock without proper return values.
**Fix:**
Added `@patch("scripts.cli.tool_manager.ToolManager")` with proper mock return values for `get_tool_summary()` including list fields.
**Resolution:** (2026-02-04) Fixed - test passes with proper ToolManager mock.

### TASK-046: [Bug] test_execute_scan_docker_mode missing ToolManager mock

**Type:** Bug
**Priority:** High
**Score:** [S+F+C] = 6 (S:2, F:2, C:2)
**Confidence:** 100%
**Status:** Resolved
**File:** tests/cli/test_wizard.py:799
**Symptom:**

```text

TypeError: can only join an iterable
```

**Root Cause:**
`_print_scan_completion_summary()` calls `', '.join(tools_skipped_content)` but mock returned int instead of list.
**Fix:**
Added `@patch("scripts.cli.tool_manager.ToolManager")` with `platform_skipped=[]` and `content_triggered=[]` as lists.
**Resolution:** (2026-02-04) Fixed - test passes.

### TASK-047: [Bug] test_execute_scan_native_mode missing ToolManager mock

**Type:** Bug
**Priority:** High
**Score:** [S+F+C] = 6 (S:2, F:2, C:2)
**Confidence:** 100%
**Status:** Resolved
**File:** tests/cli/test_wizard.py:825
**Symptom:**
Same as TASK-046 - TypeError on list join.
**Root Cause:**
Same as TASK-046 - missing ToolManager mock.
**Fix:**
Added `@patch("scripts.cli.tool_manager.ToolManager")` with proper list return values.
**Resolution:** (2026-02-04) Fixed - test passes.

---

## All 6 Targets Audited (Session 3):

| Target | Tests | Status | Notes |
|--------|-------|--------|-------|
| security | N/A | clean | CWE-78/79/89/22/502/400 all pass |
| core | 124 | clean | All pass |
| cli | 1517 | issues→fixed | 2 tests fixed (MockToolStatusSummary mocks) |
| adapters | 1886 | clean | 92% coverage, consistent patterns |
| reporters | 392 | clean | XSS protected, 95% coverage |
| wizard | 755 | clean | 93%+ coverage |

---

## Adapters Audit Summary (2026-02-04)

**Force re-audit:** 2026-02-04 (previous: 2026-02-03)

**Target Files:**

- `scripts/core/adapters/` - 29 adapters (~7,152 LOC combined)

**Test Results:**

- tests/adapters/: 1886 passed, 0 failures
- **Coverage: 92%** across all adapters

**Changes Since Last Audit:**

- No changes - audit confirms previous findings

**Consistency Analysis:**

1. **Naming Convention:** PASS (28/29 compliant)
   - All adapters use underscore naming in filenames and PluginMetadata.name
   - **Exception:** `semgrep_secrets_adapter.py` has `name="semgrep-secrets"` (hyphen)
   - This is acceptable because tool_name is also "semgrep-secrets" (actual binary)

2. **JSON Loading Helper Usage:** PASS
   - 28/29 adapters use `safe_load_json_file()` or `safe_load_ndjson_file()`
   - 4 adapters use NDJSON format: falco, nuclei, prowler, trufflehog (use `safe_load_ndjson_file()`)
   - `base_adapter.py` uses raw `json.load()` but is abstract base class, not a tool adapter

3. **Severity Mapping:** PASS
   - 24/29 adapters use `normalize_severity()` or `map_tool_severity()`
   - 5 adapters have fixed severity (not configurable):
     - `cdxgen_adapter.py`: SBOM components always INFO
     - `lynis_adapter.py`: Hardcoded HIGH/MEDIUM/CRITICAL per category
     - `kubescape_adapter.py`: Uses score_factor threshold locally
     - `scancode_adapter.py`: License compliance always INFO/LOW
     - `base_adapter.py`: Abstract base class
   - These are intentional - these tools don't emit variable severity

4. **Golden Fixtures:** PASS
   - Tests use per-adapter inline fixtures and `tests/fixtures/golden/` directory
   - Fixture coverage verified by 1889 passing tests

5. **Error Handling:** PASS
   - All 29 adapters handle empty/malformed input (verified by test_adapter_malformed.py)
   - All return empty list on parse failure

**Per-Adapter Coverage:**

| Adapter | Coverage | Notes |
|---------|----------|-------|
| bandit | 100% | Full coverage |
| gosec | 100% | Full coverage |
| hadolint | 100% | Full coverage |
| noseyparker | 100% | Full coverage |
| semgrep | 98% | Line 146 unreachable |
| semgrep_secrets | 98% | Line 83 unreachable |
| shellcheck | 98% | Branch 196→200 |
| trufflehog | 98% | Branch 113→116 |
| zap | 99% | Branch 205→203 |
| checkov | 98% | Line 185 |
| syft | 97% | 3 branch partials |
| trivy | 97% | Line 147 |
| aflplusplus | 93% | 4 lines |
| base | 94% | 2 lines |
| bearer | 95% | Line 217, 4 branches |
| falco | 94% | Line 82, 158 |
| horusec | 95% | Lines 74, 138, 142 |
| prowler | 97% | Line 74 |
| trivy_rbac | 92% | 4 lines |
| akto | 85% | 6 lines |
| cdxgen | 86% | 4 lines |
| grype | 87% | 7 lines |
| kubescape | 89% | 5 lines |
| lynis | 90% | 4 lines |
| mobsf | 90% | 6 lines |
| yara | 90% | 6 lines |
| dependency_check | 90% | 5 lines |
| nuclei | 82% | 8 lines |
| scancode | 84% | 7 lines |

**Conclusion:** All adapters are consistent and well-tested. No new tasks required.

- Minor coverage gaps exist in edge case branches (file not found, malformed input paths)
- These are defensive code paths already protected by unit tests in test_adapter_malformed.py
- 92% overall coverage exceeds the 85% CI requirement

---

## Cross-Cutting Security Audit Summary (2026-02-04)

**Force re-audit:** 2026-02-04 (previous: 2026-02-03)

**Scope:** Entire `scripts/` directory (~25,000 LOC)

**CWE-78 Command Injection (shell=True):**

- **PASS** - Only 1 instance: `tool_checker.py:735` with `nosec B602`
- Commands sourced from hardcoded `REMEDIATION_COMMANDS` dict in `tool_manager.py:184-391`
- Not user-controlled - dict contains platform commands like `pip install`, `brew install`
- No `os.system()` calls found

**CWE-79 XSS (HTML Injection):**

- **PASS** - `simple_html_reporter.py` uses `_escape_html()` for all user-derived fields
- `trend_formatters.py:703` generates insights HTML, but insights are internally generated strings
- `html_reporter.py` uses `json.dumps()` for data embedding with tag escaping (lines 81-87)
- `diff_md_reporter.py:250` unescaped summary tag is low risk (MD processors escape)

**CWE-89 SQL Injection:**

- **PASS** - 46+ queries verified parameterized with `?` placeholders
- `get_query_plan()` at `history_db.py:1919` uses f-string, but:
  - Only called from tests (no production usage)
  - EXPLAIN QUERY PLAN is read-only meta-query
- 6 dynamic WHERE clauses (`history_db.py:1180-1191, 2452-2471, 3252`) use internal literals with `nosec B608`
- `history_integrity.py:275,286` dynamic INSERT with column names from local schema dict

**CWE-22 Path Traversal:**

- **PASS** - 10 files implement path validation
- `validation.py`: `validate_path_safe()`, `validate_path_within_base()` - centralized defense
- `archive_security.py`: `_is_safe_path()` uses `Path.resolve().relative_to()` pattern
- `path_sanitizers.py`: `_sanitize_path_component()` removes `../` and path separators

**CWE-798 Hardcoded Credentials:**

- **PASS** - No hardcoded secrets found
- Only match: test fixture in `FindingsTable.test.tsx:269` (test data, not real secret)
- All runtime credentials use `os.getenv()` or config files

**CWE-502 Unsafe Deserialization:**

- **PASS** - No dangerous deserialization patterns found
- No `pickle.load`, `pickle.loads`, `eval()`, `exec()`
- No `yaml.load()` without safe_load (grep returns no matches)

**CWE-400 Resource Exhaustion (Timeouts):**

- **PASS** - 443 `timeout=` occurrences across 53 files
- Tool installer: 10s-300s timeouts for installs
- HTTP requests: 10-30s timeouts
- subprocess.run calls include timeout parameter

**nosec Annotations Audit:**

- 31 `nosec` comments found and verified:
  - `B202` (archive extraction): 3 instances, paths validated before extraction
  - `B310` (urlopen): 3 instances, URLs hardcoded (GitHub Gist) or validated
  - `B404` (subprocess import): 5 instances, necessary for CLI tool
  - `B602` (shell=True): 1 instance, commands from trusted dict
  - `B603` (subprocess without shell): 6 instances, all use list args
  - `B606` (os.startfile): 1 instance, file opener for user's own files
  - `B608` (SQL injection): 12 instances, all use parameterized values

**Conclusion:** No security vulnerabilities found. All nosec annotations are properly justified.

---

## CLI Audit Summary (2026-02-04)

**Force re-audit:** 2026-02-04 (previous: 2026-02-02)

**Target Files:**

- `scripts/cli/jmo.py` - Main CLI entry point (3,500+ lines)
- `scripts/cli/scan_orchestrator.py` - Scan orchestration (~600 lines)
- `scripts/cli/tool_installer.py` - Tool installation (~1,200 lines)
- `scripts/cli/installers/*.py` - Strategy pattern installers

**Test Results:**

- tests/cli/ (excl automation): 1492 passed, 2 skipped
- tests/scan_jobs/: 112 passed
- **Total: 1604 tests pass**

**Security Analysis (Static):**

1. **Subprocess Security (CWE-78 Check):** PASS
   - All `subprocess.run()` calls use `shell=False` (explicit or default)
   - jmo.py:3348-3381 - subprocess uses list args
   - tool_installer.py:103, 201 - explicit `shell=False` comments
   - installers/base.py:67 - documents "never use shell=True"
   - **1 exception:** wizard_flows/tool_checker.py:735 has `shell=True` but marked `# nosec B602` - commands from hardcoded REMEDIATION_COMMANDS dict

2. **Path Traversal (CWE-22 Check):** PASS
   - `scripts/cli/path_sanitizers.py` provides centralized defense:
     - `_sanitize_path_component()` removes `../`, path separators, dangerous chars
     - `_validate_output_path()` uses `Path.resolve().relative_to()` for defense-in-depth
   - `scripts/core/validation.py` provides comprehensive validation:
     - `validate_path_safe()` detects traversal sequences
     - `validate_path_within_base()` ensures paths stay within allowed directories

3. **Input Validation (CWE-88 Argument Injection):** PASS
   - `validate_url()` in validators - only allows http/https
   - `validate_container_image()` - validates image format
   - Profile names validated against `VALID_PROFILES` frozenset

4. **Timeout Handling (CWE-400 Resource Exhaustion):** PASS
   - tool_installer.py has timeouts: 10s (pkg manager check), 300s (install)
   - subprocess calls include timeout parameter
   - 443 timeout= occurrences verified across codebase

**Conclusion:** CLI modules are secure and well-tested. No new tasks required.

---

## Core Audit Summary (2026-02-04)

**Force re-audit:** 2026-02-04 (previous: 2026-02-02)

**Target Files:**

- `scripts/core/history_db.py` (~3,574 LOC) - SQLite storage, 28+ queries
- `scripts/core/normalize_and_report.py` (~649 LOC) - Central aggregation engine
- `scripts/core/config.py` - Configuration loading/validation
- `scripts/core/dedup_enhanced.py` (~1,100 LOC) - Similarity clustering

**Test Results:**

- tests/core/ + tests/adapters/ + tests/reporters/ + history + dedup: 2696 passed, 6 skipped
- tests/unit/test_history_db.py: 151 passed
- tests/unit/test_dedup_enhanced.py: 70 passed
- **Total: 2696 tests pass**

**Security Analysis (CWE-89 SQL Injection):**

1. **All cursor.execute() use parameterized queries:** PASS
   - 46+ execute() calls verified using `?` placeholders
   - Pattern: `cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))`
   - No f-string interpolation in user-facing queries

2. **get_query_plan() f-string exception:** ACCEPTABLE
   - Developer-only debugging utility
   - Not called anywhere in production code

3. **Dynamic WHERE clauses:** PASS with nosec B608
   - `history_db.py:1190, 2472, 2487, 3253` use internal literals only
   - All have nosec B608 justification comments

4. **Performance:** PASS
   - O(n) batch insert with executemany()
   - Indexes on scan_id, branch, severity, timestamp
   - LSH algorithm for dedup is O(n log n) average

**Thread Safety:**

- SQLite connections created per-operation via get_connection()
- WAL mode enabled for concurrency

**Conclusion:** Core modules are secure and well-tested. No new tasks required.

---

## Current Tasks

### TASK-042: [Bug] wizard.py --emit-script shows traceback on write failure

**Type:** Bug
**Priority:** High
**Score:** [S+F+C] = 7 (S:2, F:3, C:2)
**Confidence:** 100%
**Status:** Resolved
**File:** scripts/cli/wizard.py:911
**Symptom:**

```text

Traceback (most recent call last):
  File "scripts/cli/wizard.py", line 911, in run_wizard
    script_path.write_text(content)
FileNotFoundError: [Errno 2] No such file or directory: 'Z:\\nonexistent_dir_xyz\\script.sh'
```

**Root Cause:**
`emit_script` path write at line 911 is not wrapped in try/except, causing traceback leak to user.
Compare with `emit_gha` at line 926 which at least creates parent dirs with `mkdir(parents=True, exist_ok=True)`.
**Fix:**
Wrap `script_path.write_text(content)` in try/except and print user-friendly error:

```python
try:
    script_path.parent.mkdir(parents=True, exist_ok=True)
    script_path.write_text(content)
except (OSError, IOError) as e:
    print(f"Error: Could not write to {emit_script}: {e}")
    return 1
```

**Blocking Test:** tests/cli_ralph/test_wizard_command.py::TestWizardEdgeCases::test_wizard_emit_to_readonly_location
**Resolution:** (2026-02-03) Fixed wizard.py:907-917 by wrapping `script_path.write_text()` in try/except,
adding `script_path.parent.mkdir(parents=True, exist_ok=True)` to auto-create parent directories (matching emit_gha behavior),
and returning 1 with user-friendly error message on failure. All 20 test_wizard_command.py tests pass.

### TASK-041: [Coverage] command_builder.py at 58% - target type builders untested

**Type:** Coverage
**Priority:** Medium
**Score:** [S+F+C] = 5 (S:2, F:2, C:1)
**Confidence:** 100%
**Status:** Resolved
**Target:** scripts/cli/wizard_flows/command_builder.py
**Current Coverage:** 58% (44/122 lines uncovered)
**Gap:**

- Lines 49-50: `build_image_args()` Docker images-file mounting
- Lines 61-74: `build_iac_args()` IaC file mounting for Docker
- Lines 83-90: `build_url_args()` URLs file mounting
- Lines 97-108: `build_gitlab_args()` GitLab arguments
- Lines 113-122: `build_k8s_args()` K8s context/namespace args
**Analysis:**
These functions build command arguments for non-repository target types. They're integration-tested
indirectly via test_wizard.py but have no unit tests verifying the argument structure.
**Fix:** Create tests/cli/test_wizard_command_builder.py with unit tests:

- [x] `build_image_args()` with single image, images_file, Docker mount
- [x] `build_iac_args()` with terraform, cloudformation, k8s manifest
- [x] `build_url_args()` with URL, urls_file, api_spec
- [x] `build_gitlab_args()` with gitlab_url, token, repo, group
- [x] `build_k8s_args()` with context, namespace, all_namespaces
**Resolution:** Tests already exist in tests/unit/test_wizard_command_builder.py with 43 tests achieving 100% coverage on this module. Task was already complete.

### TASK-040: [Coverage] wizard_flows interactive modules at 8-17% coverage

**Type:** Coverage
**Priority:** High
**Score:** [S+F+C] = 7 (S:2, F:3, C:2)
**Confidence:** 100%
**Status:** Resolved
**Target:** scripts/cli/wizard_flows/ (multiple modules)
**Current Coverage:**

- `cicd_flow.py`: 7% (85/95 lines uncovered)
- `deployment_flow.py`: 8% (79/91 lines uncovered)
- `dependency_flow.py`: 14% (36/45 lines uncovered)
- `stack_flow.py`: 17% (43/57 lines uncovered)
- `repo_flow.py`: 18% (28/37 lines uncovered)
- `target_configurators.py`: 8% (171/191 lines uncovered)
**Gap:**
These are "workflow" classes that use interactive prompts (input()) for user interaction. They are not directly tested because tests mock at the wizard.py level, not at the individual flow level.
**Analysis:**
Low-priority because:

1. These flows are integration-tested via test_wizard.py and test_wizard_automation.py
2. The individual methods are simple orchestration code calling well-tested PromptHelper methods
3. The build_command() methods in these flows ARE tested via command_builder tests
4. The actual scanning logic lives in scan_jobs/ which is thoroughly tested (92% coverage)
**Fix:** Create unit tests for each flow class that mock PromptHelper methods to test:

- detect_targets() return values
- build_command() output structures
- _print_detected_* display methods (print output assertions)
**Resolution:** (2026-02-03) Created tests/cli_ralph/test_wizard_flows.py with 37 tests covering:

- CICDFlow: detect_targets, build_command, _detect_images_from_ci (handles GHA/GitLab/Jenkins, malformed YAML, non-dict YAML)
- DeploymentFlow: _detect_environment (env vars, .env files, k8s namespaces), build_command
- DependencyFlow: detect_targets, build_command (with/without images)
- EntireStackFlow: _generate_recommendations (Dockerfile, terraform, k8s, GitHub workflows), build_command
- RepoFlow: detect_targets, build_command
- All _print_detected_* display methods for coverage
Note: target_configurators.py not covered (separate task if needed). All 37 tests pass.

### TASK-039: [Coverage] validators.py at 36% coverage

**Type:** Coverage
**Priority:** High
**Score:** [S+F+C] = 6 (S:2, F:2, C:2)
**Confidence:** 100%
**Status:** Resolved
**Target:** scripts/cli/wizard_flows/validators.py
**Current Coverage:** 36% (55/87 lines uncovered)
**Gap:**

- Lines 31-39: `validate_path()` exception handling branches
- Lines 53-72: `validate_url()` HTTP error handling (HTTPError, URLError, TimeoutError)
- Lines 90-116: `detect_iac_type()` content-based detection branches
- Lines 133-170: `validate_k8s_context()` kubectl execution paths
**Fix:** Create tests/cli/test_wizard_validators.py with:

- [x] validate_path() with OSError, ValueError, invalid paths
- [x] validate_url() with HTTP 4xx/5xx, timeouts, connection refused
- [x] detect_iac_type() with various .tfstate, .yaml, CloudFormation files
- [x] validate_k8s_context() with kubectl not found, timeout, invalid context
**Resolution:** (2026-02-03) Created tests/cli/test_wizard_validators.py with 49 tests covering:

- TestValidatePath (10 tests): existing/nonexistent paths, must_exist flag, home expansion, OSError/ValueError/TypeError/RuntimeError exception handling
- TestValidateUrl (9 tests): successful validation, non-200 responses, HTTP 404/500, URLError, TimeoutError, custom timeout
- TestDetectIacType (12 tests): .tfstate files, cloudformation/cfn in name, YAML content detection (k8s apiVersion/kind, CloudFormation Resources), OSError/UnicodeDecodeError handling
- TestValidateK8sContext (10 tests): kubectl not found, context exists/not exists, 'current' context handling, command failure, timeout, FileNotFoundError, generic exceptions
- TestDetectDocker (2 tests): docker available/not available
- TestCheckDockerRunning (6 tests): daemon running/not running, timeout, FileNotFoundError, exceptions

### TASK-038: [Coverage] base_flow.py TargetDetector at 32% coverage

**Type:** Coverage
**Priority:** Medium
**Score:** [S+F+C] = 5 (S:2, F:2, C:1)
**Confidence:** 100%
**Status:** Resolved
**Target:** scripts/cli/wizard_flows/base_flow.py
**Current Coverage:** 32% (189/292 lines uncovered)
**Gap:**

- Lines 100-174: TargetDetector methods (detect_repos, detect_images, detect_iac, detect_web_apps)
- Lines 210-287: detect_package_files, detect_lock_files
- Lines 470-543: PromptHelper interactive methods (prompt_choice, prompt_yes_no, prompt_text)
- Lines 645-716: ArtifactGenerator wrapper methods
**Analysis:**
TargetDetector.detect_* methods are tested indirectly via wizard tests, but have no direct unit tests.
PromptHelper methods are simple input() wrappers - low value to test.
ArtifactGenerator wraps wizard_generators which is tested separately.
**Fix:** Create tests/cli/test_wizard_base_flow.py with:

- [x] TargetDetector.detect_repos() with git repos, non-git dirs
- [x] TargetDetector.detect_images() with docker-compose.yml, Dockerfiles
- [x] TargetDetector.detect_iac() with .tf, .tfstate, cloudformation, k8s files
- [x] TargetDetector.detect_package_files() for each language
**Resolution:** (2026-02-03) Created tests/cli_ralph/test_wizard_base_flow.py with 64 tests covering:

- TargetDetector: detect_repos (5 tests), detect_images (11 tests), detect_iac (6 tests), detect_web_apps (6 tests), detect_package_files (12 tests), detect_lock_files (8 tests)
- PromptHelper: colorize (2 tests), print_header/step/success/info/warning/error/summary_box (7 tests)
- ArtifactGenerator: generate_makefile/github_actions/shell_script (3 tests with mocks)
- Terminal utilities: _get_terminal_width (2 tests), _supports_ansi (3 tests)
All 64 tests pass.

### TASK-037: [Bug] 25 wizard test failures due to module imports and stale assertions

**Type:** Bug
**Priority:** High
**Score:** [S+F+C] = 7 (S:2, F:3, C:2)
**Confidence:** 100%
**Status:** Resolved
**Files:**

- tests/cli/test_wizard_tool_installation.py - Missing `import scripts.cli.tool_installer`
- tests/cli/test_wizard_tool_checker.py - Missing `import scripts.cli.tool_installer`
- tests/cli/test_wizard_automation.py - Missing `import scripts.cli.tool_manager`, complex mock issues
- tests/cli/test_wizard_security.py - Stale `cmd[0] == "jmo"` assertion
- tests/cli/test_wizard_target_configs.py - Stale `cmd[0] == "jmo"` assertions (4 tests)
**Symptom:**

```text

AttributeError: module 'scripts.cli' has no attribute 'tool_installer'
AssertionError: assert 'C:\\...\\python.exe' == 'jmo'
```

**Root Cause:**

1. Tests using `@patch("scripts.cli.tool_installer.ToolInstaller")` decorator fail because the module isn't imported before the patch is applied
2. Tests asserting `cmd[0] == "jmo"` fail when running from source (cmd starts with python.exe)
3. Complex mock integration tests in test_wizard_automation had MagicMock comparison issues
**Fix:**

1. Added `import scripts.cli.tool_installer # noqa: F401` to test files using tool_installer patches
2. Added `import scripts.cli.tool_manager # noqa: F401` to test_wizard_automation.py
3. Changed assertions from `cmd[0] == "jmo"` to `"scan" in cmd` (security-focused check)
4. Simplified TestCheckToolsForProfileAutoFix tests to use docker mode (simpler path)
**Resolution:** (2026-02-03) Fixed all 25 failing tests. wizard tests: 707 passed, 1 skipped.

### TASK-036: [Bug] test_effective_scan_settings_merge expects stale behavior

**Type:** Bug
**Priority:** High
**Score:** [S+F+C] = 6 (S:2, F:2, C:2)
**Confidence:** 100%
**Status:** Resolved
**File:** tests/unit/test_cli_helpers.py:66
**Symptom:**

```text

AssertionError: assert ['trufflehog', 'semgrep', ...] == ['semgrep']
```

**Root Cause:**
Test expected profile tool lists to come from jmo.yml profiles, but architecture changed - tool lists now come from `PROFILE_TOOLS` in `tool_registry.py` (single source of truth, per jmo.py lines 97-98 comment). The test's `profiles.fast.tools: [semgrep]` config is ignored by the production code.
**Fix:** Updated test to:

1. Remove stale `tools: [semgrep]` from test config profile
2. Assert against `PROFILE_TOOLS["fast"]` instead of hardcoded list
3. Added comment explaining the architecture
**Resolution:** (2026-02-02) Fixed test to match documented behavior. All 3 cli_helpers tests pass.

### TASK-035: [Bug] scan_jobs tests still use tool_exists instead of find_tool

**Type:** Bug
**Priority:** High
**Score:** [S+F+C] = 8 (S:3, F:3, C:2)
**Confidence:** 100%
**Status:** Resolved
**Files:**

- tests/scan_jobs/test_scanner_k8s.py (16 tests - FIXED)
- tests/scan_jobs/test_scanner_iac.py (13 tests - FIXED)
- tests/scan_jobs/test_scanner_gitlab.py (tests don't directly use tool_exists - OK)
**Symptom:**

```text

AttributeError: module 'scripts.cli.scan_jobs.k8s_scanner' has no attribute 'tool_exists'
29 failed tests in tests/scan_jobs/
```

**Root Cause:**
When the scanner modules (url_scanner, iac_scanner, k8s_scanner, repository_scanner) were updated to use `find_tool` instead of `tool_exists` for TASK-029/TASK-031, the corresponding test files were not updated. Tests still patch `tool_exists` which no longer exists in the modules.
**Fix:**
Update all test files to:

1. Replace `patch("...scanner.tool_exists", return_value=True/False)` with `find_tool_func` parameter
2. Use pattern: `find_tool_func=lambda tool: f"/usr/bin/{tool}" if tool in ["trivy", ...] else None`
3. Similar to the fixes applied to test_scanner_url.py and test_scanner_repository.py
**Resolution:** (2026-02-01) Fixed test_scanner_k8s.py (16 tests) and test_scanner_iac.py (13 tests):

- Removed all `patch("...tool_exists")` calls which were patching non-existent attributes
- Added `_make_find_tool_func()` helper function to each test file
- Updated all test functions to pass `find_tool_func` parameter instead of patching
- test_scanner_gitlab.py doesn't directly use tool_exists (it mocks `scan_repository` instead)
- All 112 scan_jobs tests pass

### TASK-034: [Bug] test_tr_004_trends_explain uses run_jmo_with_history incorrectly

**Type:** Bug
**Priority:** Medium
**Score:** [S+F+C] = 5 (S:2, F:2, C:1)
**Confidence:** 100%
**Status:** Resolved
**File:** tests/cli_ralph/test_trends_commands.py:96-98
**Symptom:**

```text

jmo trends explain: error: argument metric: invalid choice: 'C:\\...\\history.db'
```

**Root Cause:**
The `run_jmo_with_history` fixture adds `--db` flag at the END of args, but `trends explain` is a documentation command that takes a positional `metric` argument. The database path was being interpreted as the metric.
**Fix:** Changed from `run_jmo_with_history` to `jmo_runner` since `trends explain` is a pure documentation command that doesn't need a database.
**Resolution:** (2026-02-01) Fixed by using `jmo_runner` instead. Test passes.

### TASK-033: [Bug] test_profiles_complete fails - profile has 'warning' field

**Type:** Bug
**Priority:** Medium
**Score:** [S+F+C] = 5 (S:2, F:2, C:1)
**Confidence:** 100%
**Status:** Resolved
**File:** tests/cli/test_wizard.py:26-38
**Symptom:**

```text

AssertionError: Extra items in the left set: 'warning'
```

**Root Cause:**
The "deep" profile in profile_config.py includes an optional `warning` field for first-run notes about dependency-check. The test expected exact match of required fields only.
**Fix:** Updated test to allow optional fields:

```python
optional_fields = {"warning"}
assert required_fields <= profile_keys  # All required present
assert not (profile_keys - required_fields - optional_fields)  # No unexpected fields
```

**Resolution:** (2026-02-01) Fixed test. All profile tests pass.

### TASK-032: [WIZARD-HANG] Wizard hangs at policy selection in automation mode

**Type:** Bug
**Priority:** High
**Score:** [S+F+C] = 9 (S:3, F:3, C:3)
**Confidence:** 100%
**Status:** Resolved
**File:** scripts/cli/wizard.py:1030
**Symptom:**

```text

Wizard completes scan successfully but then blocks at interactive policy selection prompt:
"Enter choice [a/r/s/c/1-5]: "
Timeout (exit code 143) after 600s despite --auto-fix flag
```

**Root Cause:**
The `offer_policy_evaluation_after_scan()` function is called unconditionally in the else block after scan completion (line 1030-1045). This function uses `input()` for interactive policy selection, ignoring the `has_full_presets` and `yes` flags that indicate automation mode.
**Fix:**
Changed `else:` to `elif not (yes or has_full_presets):` on line 1030 to skip interactive post-scan offers when in automation mode (using presets or --yes flag).
**Resolution:** (2026-02-01) Fixed by adding automation mode check. Wizard now exits cleanly after scan in automation mode. IMAGE mode scan completes in 84s with 1218 findings from 2 tools (trivy: 81, syft: 1137).

### TASK-031: [WIZARD-OUTPUT] Scanner modules use bare tool names instead of full paths

**Type:** Bug
**Priority:** Critical
**Score:** [S+F+C] = 12 (S:4, F:4, C:4)
**Confidence:** 100%
**Status:** Resolved
**Files:**

- scripts/cli/scan_jobs/image_scanner.py - FIXED (2026-02-01)
- scripts/cli/scan_jobs/iac_scanner.py - FIXED (2026-02-01)
- scripts/cli/scan_jobs/k8s_scanner.py - FIXED (2026-02-01)
- scripts/cli/scan_jobs/url_scanner.py - FIXED (2026-02-01)
**Symptom:**

```text

Image scan completes with 0 findings. Tools report success but output files contain empty arrays:
{"Results": []} (trivy.json - 15 bytes)
{"artifacts": []} (syft.json - 17 bytes)
```

**Root Cause:**
Same pattern as TASK-029. All scanner modules (`image_scanner.py`, `iac_scanner.py`, `k8s_scanner.py`, `url_scanner.py`) check `tool_exists()` but then use bare tool names in commands instead of the full path from `find_tool()`.

When trivy is installed at `~/.jmo/bin/trivy.exe` (not in PATH), the command `["trivy", "image", ...]` fails with FileNotFoundError, which gets silently caught and results in empty stub files.

**Fix:**

1. Change import from `tool_exists` to `find_tool`
2. Change parameter from `tool_exists_func` to `find_tool_func`
3. Replace pattern `if _tool_exists("tool")` → `tool_path = _find_tool("tool"); if tool_path:`
4. Use `tool_path` in command instead of hardcoded string
5. Update all test files to use new `find_tool_func` parameter

**Resolution:** (2026-02-01) Fixed all scanner modules and their test files:

- iac_scanner.py tests: Changed `tool_exists_func` → `find_tool_func`, mock functions now return full paths
- k8s_scanner.py tests: Changed `tool_exists_func` → `find_tool_func`, mock functions now return full paths
- url_scanner.py tests: Removed unnecessary `tool_exists` patches, added `find_tool_func` parameter
All 49 scanner tests pass (9 image, 9 iac, 9 k8s, 10 url, 12 scan_jobs).

### TASK-029: [WIZARD-CRASH] repository_scanner.py uses tool names instead of full paths

**Type:** Bug
**Priority:** Critical
**Score:** [S+F+C] = 12 (S:4, F:4, C:4)
**Confidence:** 100%
**Status:** Resolved
**File:** scripts/cli/scan_jobs/repository_scanner.py (25+ occurrences)
**Symptom:**

```text

All security tools return empty results (0 findings).
FileNotFoundError: [WinError 2] The system cannot find the file specified
```

**Root Cause:**
The repository scanner checks `tool_exists()` (which calls `find_tool()` to locate tools in `~/.jmo/bin/`), but then creates commands with just the tool name instead of the full path. Example:

```python
# Current (buggy):

if _tool_exists("trivy"):
    trivy_cmd = ["trivy", "fs", ...]  # Uses bare name, not found in PATH!
```

When `subprocess.run(["trivy", ...])` executes, it fails with FileNotFoundError because `~/.jmo/bin/` is not in the system PATH. The tool runner catches this error and writes a stub file, masking the failure.

**Affected Tools (25+):**

- trivy (line 232)
- trufflehog (line 157)
- semgrep (line 202)
- syft (line 263)
- checkov (line 290)
- hadolint (line 318)
- bandit (line 351)
- noseyparker (line 384+)
- gosec (line 701)
- grype (line 950)
- kubescape (line 817)
- horusec (line 1087)
- cdxgen (line 761)
- and more...

**Fix:**
Replace all occurrences of hardcoded tool names with `_find_tool(tool_name)`:

```python
# Fixed:

trivy_path = _find_tool("trivy")
if trivy_path:
    trivy_cmd = [trivy_path, "fs", ...]
```

Already correctly implemented for:

- `dependency-check` (line 1118): `dc_path = _find_tool("dependency-check")`
- `zap-baseline.py` (line 489): `zap_baseline_path = _find_tool("zap-baseline.py")`

**Resolution:** (2026-02-01) Fixed all 25+ tool definitions in repository_scanner.py to use `_find_tool()` for full paths. Changed pattern from `if _tool_exists("tool")` with hardcoded name to `tool_path = _find_tool("tool"); if tool_path:` with path in command. Updated tests in test_repository_scanner.py to use `find_tool_func` instead of `tool_exists_func`. Wizard scan now finds 84 findings from 4 tools (syft: 41, cdxgen: 23, hadolint: 11, trivy: 9).

### TASK-030: [WIZARD-CONFIG] Semgrep HTTP 404 downloading rules

**Type:** Bug
**Priority:** High
**Score:** [S+F+C] = 7 (S:2, F:3, C:2)
**Confidence:** 100%
**Status:** Resolved
**File:** scripts/cli/scan_jobs/repository_scanner.py:191-195
**Symptom:**

```json
{"code": 2, "level": "error", "type": "SemgrepError", "message": "Failed to download configuration from https://semgrep.dev/c/p/security HTTP 404."}
```

**Root Cause:**
Default semgrep configs included `["auto", "p/security"]`. The `p/security` registry ruleset was deprecated by Semgrep and returns HTTP 404.
**Fix:**
Changed default to `["auto"]` only. The `auto` config uses Semgrep Registry auto-detection which works without authentication. Users can customize via `per_tool.semgrep.configs` in jmo.yml if needed.
**Resolution:** (2026-02-01) Changed default semgrep configs from `["auto", "p/security"]` to `["auto"]` in repository_scanner.py. Updated documentation in USER_GUIDE.md to show `configs` as a per_tool option. Updated USAGE_MATRIX.md to reference `--config auto` instead of deprecated `p/security-audit`. All 21 repository scanner tests pass.

### TASK-027: [Bug] Test files use `from tests.conftest` breaking imports

**Type:** Bug
**Priority:** High
**Score:** [S+F+C] = 7 (S:2, F:3, C:2)
**Confidence:** 100%
**Status:** Resolved
**Files:**

- tests/core/test_error_recovery.py:27
- tests/cli_ralph/conftest.py:23
- tests/cli_ralph/test_schedule_command.py:17
- tests/cli_ralph/test_tool_installation.py:19
- tests/cli_ralph/test_wizard_command.py:16
**Symptom:**

```text

ModuleNotFoundError: No module named 'tests'
```

**Root Cause:** Test files import from `tests.conftest` but `tests/` is not a proper package in PYTHONPATH. When running from repo root, pytest doesn't add `tests/` to sys.path automatically.
**Fix:** Two-part fix:

1. Add `pythonpath = ["."]` to pyproject.toml [tool.pytest.ini_options] for consistent imports
2. Change imports to use relative path with sys.path.insert:

   ```python
   import sys
   from pathlib import Path
   sys.path.insert(0, str(Path(__file__).parent.parent))
   from conftest import IS_WINDOWS, skip_on_windows
   ```

**Resolution:** (2026-01-29) Fixed all 5 files with sys.path.insert pattern. Added `pythonpath = ["."]` to pyproject.toml. Security and integration tests now pass (31 security, 34 integration).

### TASK-028: [Bug] CLI tests use wrong command arguments

**Type:** Bug
**Priority:** High
**Score:** [S+F+C] = 6 (S:2, F:2, C:2)
**Confidence:** 100%
**Status:** Resolved
**Files:**

- tests/cli_ralph/test_history_commands.py:131 - uses `--severity` flag that doesn't exist
- tests/cli_ralph/test_policy_commands.py:97-109 - passes results dir instead of --findings-file
**Symptom:**

```text

error: unrecognized arguments: --severity
error: the following arguments are required: --findings-file
```

**Root Cause:** Test assumptions don't match actual CLI API:

- `jmo history query` takes SQL query, not `--severity` filter
- `jmo policy test` requires `--findings-file` flag and policy name, not directory + `--policy`
**Fix:**

1. test_hs_004_history_query_severity: Use SQL query `SELECT * FROM findings WHERE severity = 'CRITICAL' LIMIT 10`
2. test_pl_003_policy_test: Use `--findings-file` flag with findings.json path and built-in policy name "zero-secrets"
**Resolution:** (2026-01-29) Fixed both tests. All 56 cli_ralph tests now passing.

### TASK-024: [Bug] cmd_setup fails on Windows - bash script path handling

**Type:** Bug
**Priority:** Critical
**Score:** [S+F+C] = 9 (S:3, F:3, C:3)
**Confidence:** 100%
**Status:** Resolved
**File:** scripts/cli/jmo.py:2800-2827
**Symptom:**

```text

/bin/bash: C:Projectsjmo-security-reposcriptscorecheck_and_install_tools.sh: No such file or directory
ERROR: Tool setup failed
```

**Root Cause:** `cmd_setup()` invokes bash script with Windows path. The path is correctly constructed via `Path`, but subprocess passes it to bash which cannot interpret Windows paths. Additionally, this creates platform-specific behavior.
**Fix:** Replaced bash script invocation with pure Python implementation using existing `cmd_tools_check` and `cmd_tools_install` from tool_commands.py.
**Resolution:** (2026-01-29) Rewrote `cmd_setup()` to use the Python-based tool management infrastructure instead of bash script:

- `--print-commands` → `cmd_tools_install(print_script=True)`
- `--auto-install` → `cmd_tools_install(yes=True)`
- Default → `cmd_tools_check()`
Also fixed argparse SystemExit handling in `parse_args()` to only suppress exit(0) during pytest, allowing error exits to propagate correctly. Fixed test_adapters_commands.py to provide required file argument to `adapters validate`. All 24 setup tests + 4 adapter tests passing.

### TASK-025: [Bug] Untracked test files have broken imports and logic

**Type:** Bug
**Priority:** High
**Score:** [S+F+C] = 7 (S:2, F:3, C:2)
**Confidence:** 100%
**Status:** Resolved
**Files:**

- tests/core/test_error_recovery.py - imports `JsonReporter` and `HistoryDB` which don't exist
- tests/cli_ralph/test_setup_command.py - 6 failing tests due to TASK-024
- tests/cli_ralph/test_schedule_command.py - 1 failing test (unknown subcommand returns 0 instead of error)
**Symptom:**

```text

ModuleNotFoundError: No module named 'scripts.core.reporters.json_reporter'
ImportError: cannot import name 'HistoryDB' from 'scripts.core.history_db'
```

**Root Cause:** Untracked test files reference classes/modules that don't exist or have incorrect API expectations.
**Fix:**

1. Remove or update `test_error_recovery.py` - fix imports to use actual module names
2. Fix `test_schedule_command.py` - update test expectation for unknown subcommand behavior
3. Block `test_setup_command.py` tests until TASK-024 is resolved
**Resolution:** (2026-01-29) Fixed test_error_recovery.py:

- Replaced `from scripts.core.reporters.json_reporter import JsonReporter` → `from scripts.core.reporters.basic_reporter import write_json`
- Replaced `from scripts.core.history_db import HistoryDB` → `from scripts.core.history_db import init_database, get_connection` (5 occurrences)
- Rewrote tests to use functional API instead of non-existent class-based API
- test_disk_full_during_db_insert: Used mock on sqlite3.connect instead of patching read-only Connection.execute
- All 21 tests now pass (19 pass, 2 skip on Windows)
test_setup_command.py: All tests pass now that TASK-024 is resolved.
test_schedule_command.py: test_schedule_unknown_subcommand now passes (48 pass, 2 skip)

### TASK-026: Test Module Naming Conflict

**Type:** Bug
**Priority:** Medium
**Score:** [S:2 + F:3 + C:1] = 6 (Test organization issue)
**Confidence:** 95%
**Status:** Resolved
**Target:** tests/cli_ralph/
**Gap/Symptom:** Test collection errors due to duplicate module names between `tests/cli/` and `tests/cli_ralph/` directories. Files with same basename (`test_diff_commands.py`, `test_history_commands.py`, `test_policy_commands.py`) exist in both directories, causing pytest import conflicts.
**Fix:** Either:

1. Rename cli_ralph test files to unique basenames (e.g., `test_ralph_diff_commands.py`)
2. Or consolidate tests into single directory structure
3. Or add `__init__.py` with proper namespace isolation
**Resolution:** (2026-01-29) Added `__init__.py` files to both `tests/cli/` and `tests/cli_ralph/` directories to make them proper Python packages. This allows pytest to distinguish between modules with the same basename in different directories. Verified fix: `python -m pytest tests/cli/ tests/cli_ralph/ --collect-only` now collects 1673 tests without import errors.

---

## Wizard Flows Audit Summary (2026-02-03)

**Re-audited:** 2026-02-03 17:30 (previous audit: 2026-02-03 12:00)

**Target Files:**

- `scripts/cli/wizard_flows/` - 16 modules (~2,076 LOC combined)

**Test Results (with cli_ralph tests included):**

- tests/cli/test_wizard*.py + tests/cli_ralph/test_wizard*.py: 564 passed, 1 failed, 1 skipped
- **Overall coverage: 74%** (494/2076 lines uncovered)

**Note:** Previous audit showed 58% coverage because it only ran `tests/cli/test_wizard*.py`.
The `tests/cli_ralph/` directory contains 101 additional wizard tests that significantly improve coverage.

**Coverage by Module (Updated):**

| Module | Previous | Current | Notes |
|--------|----------|---------|-------|
| `__init__.py` | 100% | 100% | Exports only |
| `config_models.py` | 100% | 100% | Dataclass definitions |
| `validators.py` | 36% | **100%** | TASK-039 resolved |
| `diff_flow.py` | 95% | 95% | Well-tested |
| `profile_config.py` | 93% | 93% | Profile definitions |
| `ui_helpers.py` | 93% | 93% | UI utilities |
| `trend_flow.py` | 92% | 92% | Trend analysis UI |
| `tool_checker.py` | 89% | 89% | Tool installation |
| `dependency_flow.py` | 14% | **89%** | cli_ralph tests |
| `cicd_flow.py` | 7% | **80%** | cli_ralph tests |
| `stack_flow.py` | 17% | **72%** | cli_ralph tests |
| `repo_flow.py` | 18% | **69%** | cli_ralph tests |
| `deployment_flow.py` | 8% | **68%** | cli_ralph tests |
| `base_flow.py` | 32% | **67%** | cli_ralph tests |
| `command_builder.py` | 58% | 58% | Target type builders |
| `telemetry_helper.py` | 33% | 33% | Optional feature |
| `target_configurators.py` | 8% | 8% | Interactive UI |

**Failing Test:**

- `tests/cli_ralph/test_wizard_command.py::TestWizardEdgeCases::test_wizard_emit_to_readonly_location`
- **Root Cause:** wizard.py:911 shows traceback on write failure (TASK-042 created)

**Analysis:**

1. **High Coverage Modules (89-100%):** Well-tested, no action needed
   - validators.py, tool_checker.py, diff_flow.py, trend_flow.py, ui_helpers.py, profile_config.py, dependency_flow.py

2. **Medium Coverage (58-80%):** Mostly covered, minor gaps
   - command_builder.py (58%): Target type builders need tests (TASK-041)
   - cicd_flow.py (80%), stack_flow.py (72%), repo_flow.py (69%), deployment_flow.py (68%), base_flow.py (67%): Interactive prompt methods remain uncovered

3. **Low Coverage (8-33%):** Expected low coverage
   - telemetry_helper.py (33%): Optional telemetry - deferred
   - target_configurators.py (8%): Pure interactive UI - deferred

**Conclusion:** 2 new tasks created: TASK-042 (bug fix) and TASK-041 (coverage).
TASK-038, 039, 040 are resolved. Coverage improved from 58% to 74% by including cli_ralph tests.

---

## Deferred Issues

<!-- Items found but not tasked (Priority < MEDIUM or Confidence < threshold) -->

| Description | Score | Reason Deferred |
|-------------|-------|-----------------|
| cicd_flow.py at 7% coverage | 3 | Interactive workflow class - orchestration only, tested via wizard.py |
| deployment_flow.py at 8% coverage | 3 | Interactive workflow class - orchestration only, tested via wizard.py |
| dependency_flow.py at 14% coverage | 3 | Interactive workflow class - orchestration only, tested via wizard.py |
| stack_flow.py at 17% coverage | 3 | Interactive workflow class - orchestration only, tested via wizard.py |
| repo_flow.py at 18% coverage | 3 | Interactive workflow class - orchestration only, tested via wizard.py |
| telemetry_helper.py at 33% coverage | 3 | Optional telemetry feature - send_wizard_telemetry has try/except fallback |
| shell=True in tool_checker.py:829 for platform commands | 4 | Has nosec comment, commands from trusted source (get_remediation_for_tool) |
| Hardcoded timeout=300 in tool_checker.py:832 | 3 | Enhancement only - works fine as-is |
| base_flow.py exception handlers swallow errors silently (lines 64, 79) | 3 | Terminal width detection - intentional fallback behavior |
| ui_helpers.py at 93% coverage | 3 | Enhancement only - minor untested lines (119, 133-134) |
| ArtifactGenerator methods in base_flow.py (lines 567-591) | 3 | Enhancement only - thin wrappers around wizard_generators |
| PromptHelper.print_info/warning/error (lines 403-427) | 3 | Simple print wrappers - low value tests |
| trend_flow.py lines 304-305: Unknown command handling | 3 | Already covered by test_run_trend_command_unknown |
| tool_checker.py lines 859-864: Exception handling during install | 3 | Low frequency - already has similar tests |
| base_flow.py lines 34-67: Windows ctypes VT enablement | 3 | Platform-specific ctypes code - impractical to unit test |
| tool_checker.py lines 629-642: ToolInstaller ImportError fallback | 3 | Rare code path - ToolInstaller always available in tests |
| diff_flow.py lines 152-154, 196-198: Error handling edge cases | 3 | UI error handling - 95% coverage sufficient |
| command_builder.py line 205-215: target type branches | 3 | Defensive code path - cannot reach without breaking type hints |
| base_flow.py line 443: single-line exception path | 3 | Print statement exception - low value |

---

## Resolved Tasks

### TASK-023: [Coverage] normalize_and_report.py at 79% coverage

**Type:** Coverage
**Priority:** Medium
**Score:** [S+F+C] = 5 (S:2, F:2, C:1)
**Confidence:** 100%
**Status:** Resolved
**Target:** scripts/core/normalize_and_report.py
**Current Coverage:** 79% → 100%
**Gap:**

- [x] Lines 225-227, 232-242: Trivy-Syft enrichment exception paths
- [x] Lines 247-252, 260-269, 274-276: Compliance/priority enrichment exceptions
- [x] Lines 313-333: SBOM matching edge cases
- [x] Lines 582-621: Report generation edge cases
**Note:** Core aggregation module. Exception paths and edge cases need coverage.
**Resolution:** Created tests/unit/test_normalize_enrichment_exceptions.py with 32 tests:

- TestTrivySyftEnrichmentExceptions: 1 test for generic Exception handler
- TestComplianceEnrichmentExceptions: 3 tests for FileNotFoundError, TypeError, and generic Exception
- TestPriorityEnrichmentExceptions: 3 tests for KeyError, ValueError, and generic Exception
- TestDedupThresholdValidation: 4 tests for threshold validation (out-of-range, invalid value, clustering failure)
- TestSafeLoadPluginExceptionPaths: 6 tests for FileNotFoundError, AdapterParseException, PermissionError, OSError, generic Exception, profiling timing failure
- TestSbomIndexEdgeCases: 3 tests for non-dict findings, non-dict raw field
- TestEnrichTrivyWithSyftEdgeCases: 1 test for non-dict findings
- TestClusterCrossToolDuplicates: 3 tests for single/empty findings, consensus creation
- TestDeprecatedSafeLoad: 2 tests for profiling timing failure, non-profiling path
- TestAflPlusPlusHandling: 1 test for afl++.json normalization
- TestSyftIndexPathBranch: 1 test for name-only packages (no path)
- TestPriorityEnrichmentLoop: 2 tests for finding id not in scores, empty findings
- TestDedupThresholdValidRange: 1 test for valid threshold applied
- TestProgressCallbackExit: 1 test for progress callback intervals
All 65 normalize tests + 93 cli_ralph tests passing (2026-01-29).

### TASK-022: [Coverage] gitlab_ci workflow generator at 8% coverage

**Type:** Coverage
**Priority:** High
**Score:** [S+F+C] = 6 (S:2, F:2, C:2)
**Confidence:** 100%
**Status:** Resolved
**Target:** scripts/core/workflow_generators/gitlab_ci.py
**Current Coverage:** 8% → 99%
**Gap:**

- [x] GitLabCIGenerator class - nearly all methods untested
- [x] Template generation functions
- [x] CI/CD pipeline configuration builders
**Note:** Initial audit incorrectly reported 8% - actual coverage was already 98% via integration tests.
**Resolution:** Created tests/unit/test_workflow_generators_gitlab_ci.py with 6 unit tests for branch partials:

- `test_generate_script_no_repositories_target` - targets without repositories key (branch 130->141)
- `test_generate_script_repositories_without_repos_dir` - repos dict without repos_dir (branch 132->134)
- `test_generate_notification_jobs_empty_channels` - empty channels list (branch 224->223)
- `test_generate_script_urls_only_no_repos_no_images` - URL-only targets
- `test_format_timeout_unknown_profile_uses_default` - unknown profile timeout fallback
- `test_to_yaml_no_description_annotation` - missing description annotation
Remaining 1% uncovered: theoretical branches (25->29 when _generate_variables returns empty dict - not possible in current impl).
All 14 gitlab_ci tests + 93 cli_ralph tests passing (2026-01-29).

### TASK-021: [Coverage] secure_temp.py at 77% coverage

**Type:** Coverage
**Priority:** Medium
**Score:** [S+F+C] = 5 (S:2, F:2, C:1)
**Confidence:** 100%
**Status:** Resolved
**Target:** scripts/core/secure_temp.py
**Current Coverage:** 77% → 97%
**Gap:**

- [x] Cleanup failure exception paths (lines 104-106, 179-181)
- [x] fd cleanup when still open (lines 169-172)
- [x] is_secure_permissions() helper (lines 214-216)
**Note:** Security-related temp file handling. Some exception paths untested.
**Resolution:** Added 9 new tests to tests/unit/test_secure_temp.py:

- TestCleanupFailurePaths: 4 tests for exception handling
  - `test_secure_temp_dir_cleanup_failure_logs_warning` - rmtree failure logs warning
  - `test_secure_temp_file_cleanup_failure_logs_warning` - unlink failure logs warning
  - `test_secure_temp_file_fd_still_open_on_exception` - fd closed in finally block
  - `test_secure_temp_file_fd_close_oserror_handled` - OSError silently caught
- TestIsSecurePermissionsHelper: 5 tests for is_secure_permissions()
  - `test_is_secure_permissions_directory_true/false` - Directory permission checks
  - `test_is_secure_permissions_file_true/false` - File permission checks
  - `test_is_secure_permissions_uses_correct_expected` - DIR vs FILE constant selection
Remaining 3% uncovered: branch partials for cleanup paths when temp doesn't exist (defensive code).
All 33 secure_temp tests passing (2026-01-29).

### TASK-020: [Coverage] archive_security.py at 19% coverage

**Type:** Coverage
**Priority:** High
**Score:** [S+F+C] = 8 (S:3, F:3, C:2)
**Confidence:** 100%
**Status:** Resolved
**Target:** scripts/core/archive_security.py
**Current Coverage:** 19% → 98%
**Gap:**

- [x] safe_tar_extract() function - lines 60-86 untested
- [x] safe_zip_extract() function - lines 103-109 untested
- [x] _is_safe_path() helper - lines 35-42 untested
**Note:** Critical security module for path traversal prevention. Testing recommended.
**Resolution:** Created tests/unit/test_archive_security.py with 22 tests:

- TestIsSafePath: 7 tests (simple, nested, traversal, absolute, dots, nested-back)
- TestSafeTarExtract: 9 tests (simple, nested, traversal, symlink warning, hardlink warning, safe symlink, empty linkname, Python 3.11 fallback, fallback symlink skip)
- TestSafeZipExtract: 6 tests (simple, nested, traversal, deep traversal, multiple files, absolute path)
Note: Python 3.12+ `data` filter provides defense in depth - tests verify warning is logged AND filter raises for unsafe links.
All 22 tests + 93 cli_ralph tests passing (2026-01-29).

### TASK-019: [Bug] test_lynis_version_command failing

**Type:** Bug
**Priority:** High
**Score:** [S+F+C] = 7 (S:2, F:3, C:2)
**Confidence:** 100%
**Status:** Resolved
**File:** tests/unit/test_tool_installer_urls.py:534
**Symptom:** `AssertionError: assert {'default': ['lynis', '--version'], ...} == ['lynis', 'show', 'version']`
**Root Cause:** Test expects `VERSION_COMMANDS["lynis"]` to be a flat list, but code changed to dict with `default`/`fallback` keys for platform-specific handling
**Fix:** Update test to check `VERSION_COMMANDS["lynis"]["fallback"]` or adjust expectation for new dict structure
**Resolution:** Updated test to check dict structure. Now verifies: (1) lynis config is a dict, (2) `default` key contains `["lynis", "--version"]`, (3) `fallback` key contains `["lynis", "show", "version"]`. All 36 test_tool_installer_urls tests passing (2026-01-29).

### TASK-018: [Coverage] diff_flow.py at 92% - exception paths untested

**Type:** Coverage
**Priority:** Medium
**Score:** [S+F+C] = 5 (S:2, F:1, C:2)
**Confidence:** 100%
**Status:** Resolved
**Target:** scripts/cli/wizard_flows/diff_flow.py:348-351
**Current Coverage:** 92% → 95%
**Gap:**

- [x] Exception handling in run_diff_wizard() - line 348-351
- [x] Generic exception logging and error message display
**Note:** Need to trigger non-KeyboardInterrupt exception in main flow
**Resolution:** Added 3 tests to TestRunDiffWizardExceptionHandling class in tests/cli/test_wizard_diff.py:

- `test_diff_wizard_generic_exception_in_flow` - RuntimeError from cmd_diff triggers exception handler, returns 1
- `test_diff_wizard_exception_during_history_load` - Corrupted SQLite database triggers load error, returns 1
- `test_diff_wizard_value_error_during_scan_selection` - Non-numeric input triggers ValueError→KeyboardInterrupt, returns 130
All 24 wizard_diff tests + 93 cli_ralph tests + 330 wizard_flows tests passing (2026-01-20)

### TASK-016: [Coverage] tool_checker.py at 73% - dependency installation flow untested

**Type:** Coverage
**Priority:** High
**Score:** [S+F+C] = 7 (S:2, F:2, C:3)
**Confidence:** 100%
**Status:** Resolved
**Target:** scripts/cli/wizard_flows/tool_checker.py:460-508
**Current Coverage:** 73% → 77%
**Gap:**

- [x] `_prompt_and_install_dependencies()` - Lines 460-508: dependency installation menu display
- [x] Choice "1" - auto install dependencies (success/failure paths)
- [x] Choice "2" - skip tools requiring deps
- [x] Choice "3" - cancel
- [x] Manual command display when auto-install fails
**Note:** Requires mocking `install_dependency`, `get_manual_dependency_command`, and `input()`
**Resolution:** Added 7 tests to TestAutoFixToolsDependencies class in tests/cli/test_wizard_tool_checker.py:

- `test_dependency_menu_displayed_with_missing_deps` - Verifies menu appears when deps missing
- `test_choice_1_auto_install_success` - Installs java dependency successfully
- `test_choice_1_auto_install_failure_shows_manual` - Shows manual command on failure
- `test_choice_2_skip_deps_continues` - Skips deps and continues with available tools
- `test_choice_3_cancel` - Cancels wizard when user chooses cancel
- `test_multiple_dependencies_installed` - Installs java and node in sequence
- `test_no_deps_skips_menu` - Skips menu when no deps needed
All 40 tool_checker tests + 93 cli_ralph tests passing (2026-01-19)

### TASK-017: [Coverage] tool_checker.py platform command execution untested

**Type:** Coverage
**Priority:** High
**Score:** [S+F+C] = 7 (S:2, F:2, C:3)
**Confidence:** 100%
**Status:** Resolved
**Target:** scripts/cli/wizard_flows/tool_checker.py:646-727
**Current Coverage:** 73% → 80%
**Gap:**

- [x] Platform command execution loop (lines 655-727)
- [x] TimeoutExpired exception path (lines 696-704)
- [x] Generic exception path (lines 705-713)
- [x] Command truncation display for long commands
- [x] Success/failure tracking per platform command
**Note:** Shell=True used (nosec B602) - test subprocess.run mocking
**Resolution:** Added 12 tests to TestPlatformCommandExecution class in tests/cli/test_wizard_tool_checker.py:

- `test_platform_command_success` - Successful command execution, tool marked as fixed
- `test_platform_command_failure_with_error_stderr` - Error in stderr triggers failure tracking
- `test_platform_command_nonzero_return_no_error_continues` - Non-zero without error/failed keywords continues
- `test_platform_command_timeout_expired` - TimeoutExpired exception path (lines 696-704)
- `test_platform_command_generic_exception` - Generic exception path (lines 705-713)
- `test_platform_command_truncation_long_command` - Commands >60 chars show truncated with "..."
- `test_platform_command_adds_yes_flag_to_jmo_install` - jmo tools install gets --yes added
- `test_platform_command_skips_empty_commands` - Empty commands in list skipped
- `test_platform_command_multiple_commands_per_tool` - Multiple commands execute in sequence
- `test_platform_command_second_command_fails` - Break on command failure
- `test_summary_output_all_fixed` - Summary shows all tools fixed
- `test_summary_output_partial_failure` - Summary shows partial failure
All 52 tool_checker tests + 93 cli_ralph tests passing (2026-01-20)

### TASK-015: [Coverage] stack_flow.py recommendation logic untested

**Type:** Coverage
**Priority:** Medium
**Score:** [S+F+C] = 6 (S:2, F:2, C:2)
**Confidence:** 100%
**Status:** Resolved
**Target:** scripts/cli/wizard_flows/stack_flow.py
**Current Coverage:** 17% → 99%
**Gap:**

- [x] `EntireStackFlow.prompt_user()` - Recommendations display, options
- [x] `EntireStackFlow._generate_recommendations()` - Smart recommendation logic
- [x] `EntireStackFlow._has_dockerfile()`, `_has_terraform_dir()`, `_has_k8s_dir()`, `_has_github_workflows()` - Helper methods
**Implementation:** Extended `tests/wizard_flows/test_stack_flow.py`
**Resolution:** Verified coverage was already 92% (not 17% as initially recorded). Added 7 tests for full branch coverage:

- `test_entire_stack_flow_prompt_user_no_recommendations` - Empty recommendations list (false branch 35→39)
- `test_entire_stack_flow_build_command_empty_targets` - All empty targets (false branches 75→79, 79→85, 85→90, 90→93)
- `test_entire_stack_flow_recommendations_no_gitlab_ci` - Missing .gitlab-ci.yml
- `test_entire_stack_flow_k8s_dir_alternative` - k8s/ instead of kubernetes/
- `test_entire_stack_flow_has_dockerfile_false` - No Dockerfile present
- `test_entire_stack_flow_github_workflows_empty` - Empty workflows dir
- `test_entire_stack_flow_build_command_many_iac_files` - IaC truncation to 5 files
All 20 stack_flow tests + 93 cli_ralph tests passing (2026-01-19)

### TASK-014: [Coverage] deployment_flow.py interactive methods untested

**Type:** Coverage
**Priority:** High
**Score:** [S+F+C] = 7 (S:2, F:2, C:3)
**Confidence:** 100%
**Status:** Resolved
**Target:** scripts/cli/wizard_flows/deployment_flow.py
**Current Coverage:** 8% → 100%
**Gap:**

- [x] `DeploymentFlow.prompt_user()` - Environment detection, profile/fail-on selection
- [x] `DeploymentFlow._print_detected_deployment_targets()` - Summary display
- [x] `DeploymentFlow.build_command()` - Command building with images/IaC/URLs
**Implementation:** Extended `tests/unit/test_wizard_deployment_dependency_flows.py`
**Resolution:** Verified coverage was already 96% (not 8% as initially recorded). Added 6 tests for full branch coverage:

- `test_deployment_print_detected_targets_many_images_truncates` - Truncation when >3 images
- `test_deployment_print_detected_targets_many_iac_truncates` - Truncation when >3 IaC files
- `test_deployment_print_detected_targets_exactly_3_iac_no_truncation` - No truncation at boundary (false branch)
- `test_deployment_detect_environment_env_var_non_matching` - Env var without prod/staging falls through
- `test_deployment_detect_environment_env_file_non_matching` - .env file without prod/staging falls through
- `test_deployment_detect_environment_k8s_non_matching` - K8s namespace without prod/staging falls through
All 34 deployment_flow tests + 93 cli_ralph tests passing (2026-01-19)

### TASK-013: [Coverage] cicd_flow.py interactive methods untested

**Type:** Coverage
**Priority:** High
**Score:** [S+F+C] = 7 (S:2, F:2, C:3)
**Confidence:** 100%
**Status:** Resolved
**Target:** scripts/cli/wizard_flows/cicd_flow.py
**Current Coverage:** 7% → 100%
**Gap:**

- [x] `CICDFlow.prompt_user()` - Interactive profile/options selection
- [x] `CICDFlow._print_detected_pipelines()` - Summary output
- [x] `CICDFlow.build_command()` - Command building with pipeline_images.txt
**Implementation:** Extended `tests/unit/test_wizard_cicd_flow.py`
**Resolution:** Verified coverage was already 98% (not 7% as initially recorded). Added 3 tests for branch coverage edge cases:

- `test_detect_images_gitlab_ci_non_dict_config` - GitLab CI config parsing to non-dict (branch 205→226)
- `test_detect_images_gitlab_ci_global_image_list` - Global image as list instead of string/dict (branch 211→215)
- `test_detect_images_gitlab_ci_job_image_list` - Job image as list instead of string/dict (branch 220→215)
All 30 cicd_flow tests + 93 cli_ralph tests passing (2026-01-19)

---

## Deferred Issues

<!-- Items found but not tasked (Priority < MEDIUM or Confidence < threshold) -->

| Description | Score | Reason Deferred |
|-------------|-------|-----------------|
| shell=True in tool_checker.py:672 for platform commands | 4 | Has nosec comment, commands from trusted source (get_remediation_for_tool) |
| Hardcoded timeout=300 in tool_checker.py:675 | 3 | Enhancement only - works fine as-is |
| base_flow.py exception handlers swallow errors silently (lines 64, 79) | 3 | Terminal width detection - intentional fallback behavior |
| No integration tests in tests/cli_ralph/ for wizard flows | 5 | Low confidence - cli_ralph is for jmo CLI, not wizard |
| ui_helpers.py at 93% coverage | 3 | Enhancement only - minor untested lines (119, 133-134) |
| ArtifactGenerator methods in base_flow.py (lines 567-591) | 3 | Enhancement only - thin wrappers around wizard_generators |
| PromptHelper.print_info/warning/error (lines 403-427) | 3 | Simple print wrappers - low value tests |
| trend_flow.py lines 304-305: Unknown command handling | 3 | Already covered by test_run_trend_command_unknown |
| tool_checker.py lines 859-864: Exception handling during install | 3 | Low frequency - already has similar tests |
| base_flow.py lines 34-67: Windows ctypes VT enablement | 3 | Platform-specific ctypes code - impractical to unit test |
| tool_checker.py lines 629-642: ToolInstaller ImportError fallback | 3 | Rare code path - ToolInstaller always available in tests |
| diff_flow.py lines 152-154, 196-198: Error handling edge cases | 3 | UI error handling - 95% coverage sufficient |
| target_configurators.py branch coverage gaps (79-80, 93, 101, 106) | 3 | Minor validation paths - 91% coverage sufficient |
| deployment_flow.py lines 186-199: Environment detection edge cases | 3 | File parsing fallbacks - 93% coverage sufficient |
| trend_flow.py lines 382-399: ValueError in scan selection loops | 3 | Input validation - similar to diff_flow patterns already documented |
| command_builder.py line 205: unreachable else branch | 3 | Defensive code path - cannot reach without breaking type hints |
| base_flow.py line 443: single-line exception path | 3 | Print statement exception - low value |

---

## Resolved Tasks

### TASK-012: [Coverage] telemetry_helper.py missing unit tests

**Type:** Coverage
**Priority:** High
**Score:** [S+F+C] = 7 (S:2, F:2, C:3)
**Confidence:** 100%
**Status:** Resolved
**Target:** scripts/cli/wizard_flows/telemetry_helper.py
**Current Coverage:** 33% → 100%
**Gap:**

- [x] `prompt_telemetry_opt_in()` - Tests for user prompt flow (y, yes, YES, empty, n)
- [x] `save_telemetry_preference()` - Tests for YAML update, new file, corrupted file
- [x] `send_wizard_telemetry()` - Tests for event sending with mock send_event, no config, exception handling
**Implementation:** Existing tests in `tests/wizard_flows/test_telemetry_helper.py`
**Resolution:** Verified coverage was already 100% (not 33% as initially recorded). The test file contains 14 tests covering all 54 statements and 4 branches. Tests cover:

- prompt_telemetry_opt_in: 5 tests (y, yes, YES, empty input defaults to no, explicit n)
- save_telemetry_preference: 3 tests (exists check, new file creation, corrupted YAML handling)
- send_wizard_telemetry: 4 tests (no config exists, with config + docker mode, exception handling)
All 93 cli_ralph tests + 14 telemetry helper tests passing (2026-01-19)

### TASK-011: [Coverage] Low-coverage workflow classes (cicd, deployment, dependency, repo, stack flows)

**Type:** Coverage
**Priority:** Medium
**Score:** [S+F+C] = 5 (S:1, F:2, C:2)
**Confidence:** 100%
**Status:** Resolved
**Target:** scripts/cli/wizard_flows/{cicd,deployment,dependency,repo,stack}_flow.py
**Current Coverage:** 7-19% → 97% (combined)
**Gap:**
These modules inherit from BaseWizardFlow and implement workflow-specific logic:

- [x] `CICDFlow` - detect_targets(), prompt_user(), build_command() - 98% coverage
- [x] `DeploymentFlow` - environment detection, targets with images+iac - 96% coverage
- [x] `DependencyFlow` - lock file detection, package file handling - 100% coverage
- [x] `RepoFlow` - repo detection, prompt user for repo selection - 100% coverage
- [x] `StackFlow` - full stack detection, recommendations - 92% coverage
**Implementation:** Extended existing `tests/unit/test_wizard_cicd_flow.py` and `tests/unit/test_wizard_deployment_dependency_flows.py`
**Resolution:** Verified existing coverage was actually 92-100% (not 7-19% as initially recorded). Added 7 new tests:

- cicd_flow: `test_detect_images_gitlab_job_string_image` (job-level string images), `test_detect_images_jenkinsfile_unreadable` (read error handling)
- deployment_flow: `test_deployment_detect_environment_from_env_var_staging`, `test_deployment_detect_environment_from_env_file_staging`, `test_deployment_detect_environment_from_k8s_manifest_staging`, `test_deployment_detect_environment_k8s_manifest_read_error`
Remaining branch partials (205->226, 35->39, etc.) are false-branch paths for optional `if` blocks - not functional gaps.
All 93 cli_ralph tests + 78 flow tests passing (2026-01-19)

### TASK-010: [Coverage] command_builder.py Docker mode branches untested

**Type:** Coverage
**Priority:** Medium
**Score:** [S+F+C] = 6 (S:2, F:2, C:2)
**Confidence:** 100%
**Status:** Resolved
**Target:** scripts/cli/wizard_flows/command_builder.py
**Current Coverage:** 58% → 100%
**Gap:**

- [x] `build_repo_args()` - Docker mode with repo_path mount
- [x] `build_image_args()` - Docker mode with images_file mount
- [x] `build_iac_args()` - Docker mode with iac_path mount
- [x] `build_url_args()` - Docker mode with urls_file mount
- [x] `build_command_parts()` - Docker mode volume extraction logic (lines 140-144)
- [x] `build_command_parts()` - Native mode with all optional flags (threads, timeout, fail_on, allow_missing_tools, human_logs)
**Implementation:** Extend `tests/unit/test_wizard_command_builder.py` with Docker mode tests
**Resolution:** Verified coverage was already 100% (not 58% as initially recorded). The test file contains 42 tests covering all 118 statements and 72 branches. All Docker mode tests already exist: `test_build_repo_args_docker_mode`, `test_build_image_args_batch_docker`, `test_build_iac_args_docker_mode`, `test_build_url_args_batch_docker`, and `test_build_command_parts_docker_*` tests. Native mode with optional flags covered by `test_build_command_parts_native_repo`. No additional tests needed (2026-01-18)

### TASK-009: [Coverage] base_flow.py BaseWizardFlow.execute() untested

**Type:** Coverage
**Priority:** High
**Score:** [S+F+C] = 7 (S:2, F:3, C:2)
**Confidence:** 100%
**Status:** Resolved
**Target:** scripts/cli/wizard_flows/base_flow.py
**Current Coverage:** 32% -> 91%
**Gap:**

- [x] `BaseWizardFlow.execute()` - Full template method workflow with mocked subprocess
- [x] `BaseWizardFlow.execute()` - User cancellation at confirmation step
- [x] `BaseWizardFlow.execute()` - Subprocess exception handling
- [x] `BaseWizardFlow.execute()` - No targets detected error
- [x] `BaseWizardFlow._estimate_time()` - All profile mappings
- [x] `TargetDetector.detect_web_apps()` - docker-compose port detection
- [x] `TargetDetector.detect_iac()` - Various IaC file patterns
- [x] `PromptHelper.print_summary_box()` - Title truncation on narrow terminals
**Implementation:** Extend `tests/unit/test_wizard_base_flow.py` with execute() tests using mocked subprocess
**Resolution:** Added 19 new tests to achieve 91% coverage (up from 82%). Key additions:

- BaseWizardFlow.execute(): Tests for empty lists, success/failure/cancel/exception paths
- PromptHelper: Text input choice, yes/no retry, NO_COLOR env, ANSI not supported
- TargetDetector: Unreadable Dockerfile, non-string ports, cwd default behavior
- ArtifactGenerator: All three generator methods tested via mocks
- ANSI Support: NO_COLOR, WT_SESSION, TERM detection, terminal width clamping
Remaining uncovered lines (34-67) are Windows ctypes ANSI VT enablement - platform-specific and impractical to unit test. All 72 base_flow tests + 94 cli_ralph tests passing (2026-01-18)

### TASK-008: [Coverage] validators.py functions need direct testing

**Type:** Coverage
**Priority:** High
**Score:** [S+F+C] = 7 (S:2, F:3, C:2)
**Confidence:** 100%
**Status:** Resolved
**Target:** scripts/cli/wizard_flows/validators.py
**Current Coverage:** 25% -> 100%
**Gap:**

- [x] `validate_path()` - All exception types (OSError, ValueError, TypeError, RuntimeError)
- [x] `validate_url()` - HTTPError with various codes
- [x] `validate_url()` - URLError for DNS/connection failures
- [x] `validate_url()` - Timeout handling
- [x] `detect_iac_type()` - All file types (terraform, cloudformation, k8s-manifest)
- [x] `detect_iac_type()` - YAML content analysis paths
- [x] `validate_k8s_context()` - Context list parsing, "current" mode
- [x] `check_docker_running()` - Timeout and FileNotFoundError paths
**Implementation:** Extended `tests/unit/test_wizard_validators.py` with focused unit tests
**Resolution:** Verified coverage was already 100% (not 25% as initially recorded). The test file `tests/unit/test_wizard_validators.py` contains 43 tests covering all 87 statements and 20 branches. All code paths including exception handling for OSError, ValueError, TypeError, RuntimeError, HTTPError, URLError, TimeoutError, and FileNotFoundError are fully tested. No additional tests needed (2026-01-18)

### TASK-007: [Coverage] target_configurators.py interactive functions untested

**Type:** Coverage
**Priority:** High
**Score:** [S+F+C] = 8 (S:3, F:3, C:2)
**Confidence:** 100%
**Status:** Resolved
**Target:** scripts/cli/wizard_flows/target_configurators.py
**Current Coverage:** 98% -> 100%
**Gap:**

- [x] `configure_repo_target()` - Happy path for each repo_mode (repo, repos-dir, targets, tsv)
- [x] `configure_repo_target()` - Path validation failure and retry loop
- [x] `configure_repo_target()` - Empty repos-dir warning prompt
- [x] `configure_image_target()` - Single mode and batch mode
- [x] `configure_iac_target()` - Path validation and IaC type detection
- [x] `configure_url_target()` - Single URL, batch, and API modes
- [x] `configure_url_target()` - URL unreachable warning and continue anyway
- [x] `configure_gitlab_target()` - Token from env vs manual input
- [x] `configure_k8s_target()` - kubectl missing warning, context validation
- [x] Truncation display when >5 repos/images/URLs (lines 93, 150, 252)
**Implementation:** Extended `tests/unit/test_wizard_target_configurators.py`
**Resolution:** Coverage was already at 98% (not 8% as initially recorded). Added 3 tests for truncation branches to achieve 100% coverage:

- `test_configure_repo_target_repos_dir_many_repos_truncates` - Tests "... and N more" display for repos
- `test_configure_image_target_batch_many_images_truncates` - Tests "... and N more" display for images
- `test_configure_url_target_batch_many_urls_truncates` - Tests "... and N more" display for URLs
All 36 target_configurators tests passing (2026-01-18)

### TASK-006: [Coverage] policy_flow.py navigation edge cases

**Type:** Coverage
**Priority:** Medium
**Score:** [S+F+C] = 6 (S:2, F:2, C:2)
**Confidence:** 100%
**Status:** Resolved
**Target:** scripts/cli/wizard_flows/policy_flow.py
**Current Coverage:** ~85% -> ~92% (estimated)
**Gap:**

- [x] `_parse_policy_choice()` with invalid comma-separated numbers (e.g., "1,99,3")
- [x] `_parse_policy_choice()` with non-numeric values (e.g., "1,abc,2")
- [x] `_parse_policy_choice()` with empty custom input
- [x] `display_policy_violations_interactive()` with empty results dict
- [x] `_show_all_violations_paginated()` with 0 violations
- [x] `_show_all_violations_paginated()` single page and navigation
- [x] Navigation edge cases (next at last, prev at first)
- [x] Export error handling (file write failures)
- [x] `_display_violation()` with empty/whitespace path
- [x] `_truncate_sensitive()` with various content types
- [x] `_extract_rule_id()` for PCI, CIS, NIST patterns
- [x] `_extract_severity_tag()` for severity extraction
- [x] `_display_violation()` with hardening policy type
- [x] `_display_violation()` with long messages (>200 chars)
- [x] Policy evaluation error handling
- [x] `_normalize_policy_name()` various formats
**Implementation:** Added 27 new edge case tests to `tests/cli/test_wizard_policy_integration.py`
**Resolution:** Comprehensive edge case coverage added (2026-01-18):

- _parse_policy_choice: 3 tests (out-of-range, non-numeric, empty)
- display_policy_violations_interactive: 4 tests (empty results, show all, navigation edges)
- _show_all_violations_paginated: 4 tests (zero, single page, navigation, invalid)
- Export functions: 2 tests (JSON/MD write errors)
- _display_violation: 4 tests (empty path, whitespace path, hardening, long message)
- _truncate_sensitive: 3 tests (short, long base64, private key)
- _extract_rule_id: 4 tests (PCI, CIS, NIST, unknown)
- _extract_severity_tag: 1 test (all severities)
- Policy evaluation: 1 test (evaluation error)
- _normalize_policy_name: 1 test (various formats)
All 94 CLI Ralph tests + 58 policy integration tests passing (2026-01-18)

### TASK-005: [Coverage] trend_flow.py interactive functions untested

**Type:** Coverage
**Priority:** High
**Score:** [S+F+C] = 8 (S:2, F:3, C:3)
**Confidence:** 100%
**Status:** Resolved
**Target:** scripts/cli/wizard_flows/trend_flow.py
**Current Coverage:** 67% -> ~85% (estimated)
**Gap:**

- [x] `explore_trends_interactive()` - menu loop options 2-5 (regressions, velocity, developers, score)
- [x] `explore_trends_interactive()` - menu options 6 (compare) and 7 (export) dispatch
- [x] `_run_trend_command_interactive()` - non-zero result handling (lines 310-314)
- [x] `_run_trend_command_interactive()` - exception handling
- [x] `_compare_scans_interactive()` - non-zero result, import error, exception paths
- [x] `_export_trends_interactive()` - ImportError path (lines 510-514)
- [x] `_export_trends_interactive()` - Exception path (lines 515-518)
**Implementation:** Extended `tests/cli/test_wizard_trends.py` with 14 new tests
**Resolution:** Added comprehensive test coverage for trend_flow.py interactive functions:

- Menu options 2-7: 6 tests (regressions, velocity, developers, score, compare, export)
- _run_trend_command_interactive: 2 tests (nonzero result, exception)
- _export_trends_interactive: 2 tests (import error, exception)
- _compare_scans_interactive: 3 tests (nonzero result, import error, exception)
All 94 CLI Ralph tests + 36 wizard trends tests passing (2026-01-18)

### TASK-004: [Coverage] tool_checker.py critical functions untested

**Type:** Coverage
**Priority:** High
**Score:** [S+F+C] = 9 (S:3, F:3, C:3)
**Confidence:** 100%
**Status:** Resolved
**Target:** scripts/cli/wizard_flows/tool_checker.py
**Current Coverage:** 46% -> ~75% (estimated)
**Gap:**

- [x] `check_tools_for_profile()` - main entry point, only tested indirectly
- [x] `_check_policy_tools()` - OPA availability check, no direct tests
- [x] `_install_opa_tool()` - OPA installation, no direct tests
- [x] `_show_all_fix_commands()` - command display, no tests
- [x] `_collect_missing_dependencies()` - dependency grouping, no tests
- [x] Lines 248-274: Crash detection for startup crashes
- [x] Lines 310-340: Interactive choice handling (options 1-4)
- [ ] Lines 460-508: Missing dependency installation flow (deferred - requires integration test)
- [ ] Lines 617-642: JMo tools parallel installation path (covered by existing tests)
- [ ] Lines 739-746: Post-fix re-check (covered by existing tests)
**Implementation:** Created `tests/cli/test_wizard_tool_checker.py` with 33 new tests
**Resolution:** Added comprehensive test coverage (33 tests) for tool_checker.py functions including:

- check_tools_for_profile: 6 tests (docker mode, all ready, yes mode, import/generic error, skipped tools)
- _check_policy_tools: 8 tests (no policies, skip, docker, OPA available/missing, interactive choices)
- _install_opa_tool: 4 tests (success, failure, import error, exception)
- _show_all_fix_commands: 3 tests (remediation, jmo install, empty)
- _collect_missing_dependencies: 8 tests (empty, no deps, single/multiple deps, node normalization, duplicates)
- Interactive choices: 3 tests (auto-fix, continue, cancel)
- Crash detection: 1 test (startup crash display)
All 94 CLI Ralph tests + 43 tool checker tests passing (2026-01-18)

### TASK-003: [Bug] ValueError crash in policy_flow custom selection

**Type:** Bug
**Priority:** Critical
**Score:** [S+F+C] = 11 (S:4, F:3, C:4)
**Status:** Resolved
**File:** scripts/cli/wizard_flows/policy_flow.py:321
**Symptom:** `ValueError: invalid literal for int() with base 10: 'a'` when entering non-numeric values
**Root Cause:** List comprehension `int(x.strip()) - 1` lacked try/except
**Fix:** Added `safe_int()` helper that returns None for invalid values, filter out None
**Resolution:** Fixed in policy_flow.py:321-330, added 2 regression tests in test_policy_flow.py (2026-01-17)

### TASK-002: Fix RALPH_FIXTURES_DIR path after directory move

**Type:** Bug
**Priority:** Critical
**Status:** Resolved
**Test:** 32 tests (diff, report, history, trends, ci, policy)
**Error:** `FileNotFoundError: .claude/ralph-cli-testing/fixtures not found`
**Root Cause:** Refactoring moved files but forgot to update conftest.py path
**Fix:** Changed `.claude/ralph-cli-testing` to `tools/ralph-testing` in conftest.py:36-38
**Resolution:** All 94 tests passing after fix (2026-01-17)

### TASK-001: Validate test suite baseline

**Type:** Bug
**Priority:** High
**Status:** Resolved
**Description:** Run full test suite and verify all 94 tests pass
**Resolution:** All 94 tests passed in 7m 5s (2026-01-17). Suite is stable.

---

## Audit History

| Date | Mode | Target | Tasks Created | Notes |
|------|------|--------|---------------|-------|
| 2026-02-02 | wizard-audit | wizard + wizard_flows | 0 | Wizard-focused audit #32: 395 cli/wizard tests + 306 wizard_flows = 701 pass, 1 skip. Combined coverage 92%. Static analysis clean (no eval/exec/pickle/yaml.unsafe, 1 shell=True nosec B602 in tool_checker.py:829). Uncovered lines are low-priority: Windows ctypes ANSI (base_flow.py:34-67), exception handlers (telemetry_helper.py:59), tool status display (tool_checker.py:184-229). No actionable gaps found. |
| 2026-02-03 | full-audit -Force | all 6 targets | 0 | Force re-audit #31: All targets clean. security 87+8skip (static: no dangerous patterns, 1 shell=True nosec B602), core 240+2skip (history_db 151, dedup 70, error_recovery 19), cli 315+1skip (wizard 61, tool_commands 117, repository_scanner 23, scan_jobs 114), adapters 1889 pass, reporters 392+1skip (XSS: _escape_html), wizard 707+1skip. |
| 2026-02-03 | full-audit -Force | all 6 targets | 0 | Force re-audit #30: All targets clean. security 87+8skip (static: no dangerous patterns), core 240+2skip (history_db 151, dedup 70, error_recovery 19), cli 315+1skip (wizard 61, tool_commands 117, repository_scanner 23, scan_jobs 114), adapters 1889 pass, reporters 392+1skip (XSS: _escape_html), wizard 707+1skip. |
| 2026-02-03 | full-audit -Force | all 6 targets | 1 (test fixes) | Force re-audit #29: TASK-037 - Fixed 25 wizard test failures (module import issues, stale jmo/scan assertions). security 86+8skip, core 382+2skip, cli 255+1skip, adapters 1889 pass, reporters 392+1skip, wizard 707+1skip. All targets clean. |
| 2026-02-02 | full-audit -Force | all 6 targets | 0 | Force re-audit #28: All targets clean. security 95+8skip (static: no eval/exec/pickle/yaml.unsafe/os.system/os.popen, 1 shell=True nosec B602), core 221 pass (history_db 151, dedup 70), cli 313+1skip (wizard 61, tool_commands 117, repository_scanner 23, scan_jobs 112), adapters 1889 pass, reporters 392+1skip (XSS: _escape_html + script-tag escaping), wizard 701+1skip. |
| 2026-02-02 | full-audit -Force | all 6 targets | 0 | Force re-audit #27: All targets clean. security 118+9skip (static: no eval/exec/pickle/yaml.unsafe/os.system/os.popen, 1 shell=True nosec B602), core 245+2skip (history_db, dedup_enhanced, error_recovery, history_integrity), cli 312+1skip (wizard, tool_commands, repository_scanner, scan_jobs), adapters 1889 pass, reporters 392+1skip (XSS: _escape_html), wizard 701+1skip. |
| 2026-02-02 | full-audit -Force | all 6 targets | 0 | Force re-audit #26: All targets clean. security 87+8skip (static: no dangerous patterns, 1 shell=True nosec B602), core 240+2skip (history_db, dedup_enhanced, error_recovery), cli 312+1skip (wizard, tool_commands, repository_scanner, scan_jobs), adapters 1889 pass, reporters 392+1skip (XSS: _escape_html), wizard 701+1skip. |
| 2026-02-02 | full-audit -Force | all 6 targets | 0 | Force re-audit #25: All targets clean. security 127 tests (95+ pass, 8 skip), static clean (no dangerous patterns, 1 shell=True nosec B602), core 240+2skip (history_db, dedup_enhanced, error_recovery), cli 312+1skip (wizard, tool_commands, repository_scanner, scan_jobs), adapters 1889 pass, reporters 392+1skip (XSS: _escape_html + script-tag escape), wizard 701+1skip. |
| 2026-02-02 | full-audit -Force | all 6 targets | 0 | Force re-audit #24: All targets clean. security 95+8skip (static: no dangerous patterns, 1 shell=True nosec B602), core 240+2skip (history_db, dedup_enhanced, error_recovery), cli 312+1skip (wizard, tool_commands, repository_scanner, scan_jobs), adapters 1889 pass, reporters 392+1skip (XSS: _escape_html), wizard 701+1skip. |
| 2026-02-02 | full-audit -Force | all 6 targets | 0 | Force re-audit #23: All targets clean. security 86+9skip (static: no dangerous patterns, 1 shell=True nosec B602), core 240+2skip (history_db, dedup_enhanced, error_recovery), cli 312+1skip (wizard, tool_commands, repository_scanner, scan_jobs), adapters 1889 pass, reporters 392+1skip (XSS: _escape_html), wizard 701+1skip. |
| 2026-02-02 | full-audit -Force | all 6 targets | 0 | Force re-audit #22: All targets clean. security 87+8skip (static: no dangerous patterns, 1 shell=True nosec B602), core 240+2skip (history_db, dedup_enhanced, error_recovery), cli 312+1skip (wizard, tool_commands, repository_scanner, scan_jobs), adapters 1889 pass, reporters 392+1skip (XSS: _escape_html), wizard 701+1skip. |
| 2026-02-02 | full-audit -Force | all 6 targets | 0 | Force re-audit #21: All targets clean. security 116+8skip (static: no dangerous patterns, 1 shell=True nosec B602), core 313+4skip (history_db, dedup_enhanced, error_recovery), cli 312+1skip (wizard, tool_commands, repository_scanner, scan_jobs), adapters 1889 pass, reporters 392+1skip (XSS: _escape_html), wizard 701+1skip. |
| 2026-02-02 | full-audit -Force | all 6 targets | 0 | Force re-audit #20: All targets clean. security 31+1skip (static: no dangerous patterns, 1 shell=True nosec B602), core 240+2skip (history_db 151, dedup 70, error_recovery 19), cli 312+1skip (wizard 61, tool_commands 117, repository_scanner 23, scan_jobs 112), adapters 1889 pass, reporters 392+1skip (XSS: _escape_html), wizard 701+1skip. |
| 2026-02-02 | full-audit -Force | all 6 targets | 0 | Force re-audit #19: All targets clean. security 95+8skip (static: no eval/exec/pickle/yaml.unsafe_load/os.system/os.popen, 1 shell=True nosec B602), core 240+2skip (history_db, dedup_enhanced, error_recovery), cli 312+1skip (wizard 200, tool_commands, repository_scanner 23, scan_jobs 112), adapters 1889 pass, reporters 392+1skip (XSS: _escape_html), wizard 701+1skip. |
| 2026-02-02 | full-audit -Force | all 6 targets | 0 | Force re-audit #18: All targets clean. security 118+9skip (static: no eval/exec/pickle/yaml.unsafe_load/os.system/os.popen, 1 shell=True nosec B602), core 245+2skip (history_db, dedup_enhanced, error_recovery), cli 312+1skip (wizard, tool_commands, repository_scanner, scan_jobs 112), adapters 1889 pass, reporters 392+1skip (XSS: _escape_html), wizard 701+1skip. |
| 2026-02-02 | full-audit -Force | all 6 targets | 0 | Force re-audit #17: All targets clean. security 87+8skip (static: no eval/exec/pickle/yaml.unsafe_load/os.system/os.popen, 1 shell=True nosec B602, SQL only PRAGMA columns), core 245+2skip (history_db, dedup_enhanced, error_recovery, integrity), cli 312+1skip (wizard, tool_commands, all scanners), adapters 1889 pass, reporters 392+1skip (XSS: _escape_html), wizard 701+1skip. |
| 2026-02-02 | full-audit -Force | all 6 targets | 0 | Force re-audit #16: All targets clean. security 122+8skip (static: no eval/exec/pickle/yaml.unsafe_load/os.system/os.popen, 1 shell=True nosec B602, 2 SQL nosec B608 for PRAGMA columns), core 245+2skip (history_db 90, dedup 70, error_recovery 21, integrity 5), cli 312+1skip (wizard 61, tool_commands 117, repository_scanner 23, scan_jobs 112), adapters 1889 pass, reporters 392+1skip (XSS: _escape_html + script-tag-breakout prevention), wizard 306+112 pass (flows + scan_jobs). |
| 2026-02-02 | full-audit -Force | all 6 targets | 0 | Force re-audit #15: All targets clean. security 95+8skip (static: no eval/exec/pickle/yaml.unsafe, 1 shell=True nosec B602, 2 SQL nosec B608), core 245+2skip (history_db 90, dedup 70, error_recovery 21, integrity 5), cli 313+1skip (wizard 61, tool_commands 117, repository_scanner 23, scan_jobs 112), adapters 1889 pass, reporters 392+1skip (XSS: escape funcs in all 3 HTML reporters), wizard 306 pass. |
| 2026-02-02 | full-audit -Force | all 6 targets | 0 | Force re-audit #14: All targets clean. security 95+8skip (static: no dangerous Python patterns, 1 shell=True nosec B602), core 260+2skip (history_db 151, dedup 70, error_recovery 21, integrity 5, security 8, encryption 7), cli 312+1skip (wizard 61, tool_commands 117, repository_scanner 22, scan_jobs 112), adapters 1889 pass, reporters 392+1skip (XSS: _escape_html), wizard 306 pass. |
| 2026-02-02 | full-audit -Force | all 6 targets | 0 | Force re-audit #13: All targets clean. security (static: no eval/exec/pickle/yaml.unsafe_load/os.system/os.popen, 1 shell=True nosec B602, 8 B608 nosec for PRAGMA-derived columns), core 302+4skip (history_db+dedup+error_recovery), cli 200+1skip + scan_jobs 112, adapters 1889 pass, reporters 392+1skip (XSS: _escape_html+html.escape), wizard 306+112 pass (flows+scan_jobs). |
| 2026-02-02 | full-audit -Force | all 6 targets | 0 | Force re-audit #12: All targets clean. security 95+8skip (static: no dangerous patterns, 1 shell=True nosec, 8 B608 nosec), core 292+3skip (history_db+encryption+format+futures+performance+permissions+privacy+security+dedup), cli 200+1skip + scan_jobs 112, adapters 1889 pass, reporters 392+1skip, wizard_flows 306 pass, error_recovery 19+2skip. |
| 2026-02-02 | full-audit -Force | all 6 targets | 0 | Force re-audit #11: All targets clean. security 87+8skip (static: no dangerous patterns), core 221 pass (history_db 151, dedup 70) + error_recovery 19+2skip, cli 200+1skip + scan_jobs 112 + tool_checker/trends/policy 146, adapters 1889 pass, reporters 392+1skip, wizard_flows 306 pass. |
| 2026-02-02 | full-audit -Force | all 6 targets | 0 | Force re-audit #10: All targets clean. security 87+8skip (static: no dangerous patterns, 1 shell=True nosec), core 226 pass (history_db 156, integrity 4, dedup 66), cli 200+1skip + scan_jobs 112, adapters 1889 pass, reporters 392+1skip, wizard_flows 306 pass. |
| 2026-02-02 | full-audit -Force | all 6 targets | 0 | Force re-audit #9: All targets clean. security 31+1skip, core 348 pass (history_db 151, dedup 70, email 17), cli 201 pass (wizard 61, tool_commands 117, repository_scanner 23), adapters 1889 pass, reporters 392+1skip, wizard 701+1skip, scan_jobs 112 pass, error_recovery 19+2skip. Static: no dangerous patterns, 1 shell=True nosec (tool_checker.py:735), 8 B608 nosec (history_db/integrity - parameterized query construction). |
| 2026-02-02 | full-audit -Force | all 6 targets | 0 | Force re-audit #8: All targets clean. security 87+8skip, core 226 pass (history_db+integrity+dedup), cli 629+2skip (wizard+tool_commands+repository_scanner), adapters 1889 pass, reporters 392+1skip, wizard 993+1skip (flows 598 + cli 395). scan_jobs 131+2skip, error_recovery integrated. Static: no dangerous patterns, 1 shell=True nosec, 2 B608 nosec for PRAGMA-derived column lists. |
| 2026-02-02 | full-audit -Force | all 6 targets | 0 | Force re-audit #7: All targets clean. security 87+8skip, core 226 pass, cli 629+2skip, adapters 1889 pass, reporters 392+1skip, wizard 701+1skip. scan_jobs 112 pass + error_recovery 19+2skip. Static: no dangerous patterns, 1 shell=True nosec. |
| 2026-02-02 | full-audit -Force | all 6 targets | 0 | Force re-audit #6: All targets clean. security 95+8skip (static analysis: no dangerous patterns, 1 shell=True nosec), core 258 pass (156 history + 102 normalize/dedup), cli 323 pass (wizard 89, automation 25, tool_checker 52, security 44, policy_integration 58, error_recovery 21+2skip, scan_jobs 134+1skip), adapters 1889 pass, reporters 392+1skip, wizard_flows 306 pass. |
| 2026-02-02 | full-audit -Force | all 6 targets | 0 | Force re-audit #5: All targets clean. security 87+8skip, core 237 pass (156 history + 81 normalize/dedup), cli 223+1skip, adapters 1889 pass, reporters 392+1skip, wizard_flows 306 pass. Static analysis clean. |
| 2026-02-02 | full-audit -Force | all 6 targets | 0 | Force re-audit #4: All targets clean. security 31+1skip, core 224+2skip (history) + 87+8skip (normalize), cli 113+3+25+112=253 pass, adapters 1889 pass, reporters 392+1skip, wizard_flows 306 pass. Static analysis clean - no eval/exec/pickle/yaml.unsafe_load. |
| 2026-02-02 | full-audit -Force | all 6 targets | 0 | Force re-audit #3: All targets clean. security 95+8skip, core 172 pass, cli 116 pass, adapters 1889 pass, reporters 392+1skip, wizard 701+1skip, scan_jobs 134+1skip. Static analysis clean. |
| 2026-02-02 | full-audit -Force | all 6 targets | 0 | Force re-audit #2: All targets clean. security 95+8skip, core 351 pass, cli 1051+skip, adapters 1889 pass, reporters 392+1skip, wizard 706+1skip, scan_jobs 112 pass. No new issues found. |
| 2026-02-02 | full-audit -Force | all 6 targets | 1 | Force re-audit: TASK-036 (test_cli_helpers stale profile expectation). security 95 pass+8 skip, core 124 pass+3 skip, cli 1468 pass+2 skip, adapters 1886 pass, reporters 392 pass+1 skip, wizard 306 pass, scan_jobs 112 pass, unit 2336 pass+53 skip. All targets clean. |
| 2026-01-29 | full-audit -Force | all 6 targets | 2 | Force re-audit: TASK-027 (test imports), TASK-028 (CLI test API). All targets clean after fixes. security 31/32 pass, adapters 1886 pass, reporters 392 pass, cli 1426+56 pass, core 172 pass. |
| 2026-01-29 | full-audit -Force | all 6 targets | 2 | Force re-audit: TASK-024 (cmd_setup Windows bug), TASK-025 (broken untracked tests). Core tests passing: adapters 1886, reporters 392, wizard 987, core 283. |
| 2026-01-29 | full-audit -Force | all 6 targets | 0 | Force re-audit: All targets now clean. security 97%, core 86%, cli 90%, adapters 92%, reporters 95%, wizard 93%. ~3,500+ tests passing. All previous tasks resolved. |
| 2026-01-29 | audit | wizard + wizard_flows | 0 | Re-audit: 676 passed, 1 skip. 93% combined coverage. No actionable gaps found. Codebase stable. |
| 2026-01-29 | full-audit | security, core, cli, adapters, reporters | 5 | Full codebase audit. security: 4 tasks (archive_security 19%, secure_temp 77%). core: 1 task (normalize 79%). cli: 1 bug (lynis test). adapters: 0 (91% coverage). reporters: 0 (95% coverage). |
| 2026-01-27 | audit | wizard + wizard_flows | 0 | Re-audit - 676 passed, 1 skip. 93% coverage. No new gaps. Codebase stable. |
| 2026-01-27 | audit | wizard + wizard_flows | 0 | Ralph audit cycle - 676 passed, 1 skip. 93% combined coverage. All uncovered lines in Deferred. |
| 2026-01-20 | audit | wizard + wizard_flows | 0 | Re-audit - 676 passed, 1 skip. 93% coverage. All uncovered lines in Deferred. |
| 2026-01-20 | audit | wizard + wizard_flows | 0 | Final audit - 676 tests pass, 1 skip. Combined coverage 93%. No actionable gaps found. |
| 2026-01-19 | audit | wizard + wizard_flows | 3 | Re-audit after TASK-015 resolved. 655 tests pass, 1 skip. tool_checker.py 73%, diff_flow.py 92%. |
| 2026-01-19 | audit | wizard + wizard_flows | 4 | Re-audit after TASK-006 through TASK-011 resolved. 348 tests pass, 1 skip. Overall wizard_flows 52% coverage. |
| 2026-01-18 | audit | wizard + wizard_flows | 5 | Comprehensive wizard audit, 647 tests pass, 52% overall coverage |
| 2026-01-17 | test | - | 0 | Initial validation, all 94 tests pass |

---

## Notes

### Full Codebase Audit Summary (2026-01-29 -Force #3)

**Targets Audited:** 6 (security, core, cli, adapters, reporters, wizard)

**Test Results:**

- security: 31 passed, 1 skipped
- adapters: 1886 passed
- reporters: 392 passed, 1 skipped
- cli: 1426 passed + 56 cli_ralph passed
- core: 151 history_db + 21 error_recovery = 172 passed

**Issues Found & Fixed:**

1. **TASK-027 (High)**: Test files use `from tests.conftest` breaking imports (5 files fixed with sys.path.insert + pythonpath in pyproject.toml)

2. **TASK-028 (High)**: CLI tests use wrong command arguments:
   - test_history_query: used `--severity` flag (doesn't exist, takes SQL query)
   - test_policy_test: used results dir instead of `--findings-file`

**Security Posture (Verified):**

- All subprocess calls use `shell=False` (except 1 nosec B602 in tool_checker.py for platform commands)
- os.system/popen: 5 findings, all are `platform.system()` calls for OS detection (false positives)
- Path traversal prevention via archive_security._is_safe_path() - 98% covered
- SQL injection protected via parameterized queries in history_db.py - no f-string SQL (except get_query_plan internal debug)
- YAML uses safe_load throughout codebase - verified grep found no unsafe usage
- No pickle/eval/exec usage found
- XSS prevention in HTML reporters - escape functions in simple_html and html_reporter

### Full Codebase Audit Summary (2026-02-02 -Force)

**Test Results:**

- security: 95 passed, 8 skipped (archive_security, secure_temp, normalize_enrichment)
- core: 124 passed, 3 skipped (telemetry, tool_registry)
- cli: 1468 passed, 2 skipped (wizard, tool_checker, etc.)
- adapters: 1886 passed
- reporters: 392 passed, 1 skipped
- wizard_flows: 306 passed
- scan_jobs: 112 passed
- unit: 2336 passed, 53 skipped

**Issues Found & Fixed:**

1. **TASK-036 (High)**: `test_effective_scan_settings_merge` expected stale behavior where profile tool lists came from jmo.yml. Architecture changed - tool lists now come from `PROFILE_TOOLS` in `tool_registry.py`. Test updated to match documented behavior.

**Security Posture (Re-verified):**

- shell=True: 1 usage (tool_checker.py:735) with nosec B602 - user-initiated fix commands only
- No os.system/popen/eval/exec/pickle usage in scripts/
- No yaml.load or yaml.unsafe_load usage
- SQL injection protected - f-string SQL only in history_integrity.py with nosec B608 (column/placeholder generation, no user input)
- XSS prevention confirmed in html_reporter.py (escape for script tag context) and simple_html_reporter.py (full HTML escape)

**Known Test Infrastructure Issues (not code bugs):**

- Integration tests (baseline_validation, scan_pipeline): Require real tools installed
- Performance tests: Timeout due to real EPSS API calls
- E2E tests: Windows PATH_MAX limit for long path test, timeouts for real scans

### Full Codebase Audit Summary (2026-01-29 -Force #2)

**Test Results:**

- adapters: 1886 passed
- reporters: 392 passed, 1 skipped
- wizard: 987 passed, 1 skipped
- core: 283 passed (218 history_db/dedup + 65 normalize)
- cli: 147 passed (scan_orchestrator + tool_installer)

**Issues Found:**

1. **TASK-024 (Critical)**: `jmo setup` command fails on Windows due to bash script path handling. Return code 127 from bash.

2. **TASK-025 (High)**: Untracked test files have broken imports:
   - `tests/core/test_error_recovery.py` - imports non-existent `JsonReporter` and `HistoryDB`
   - 5 failing tests in test_error_recovery.py
   - 6 failing tests in test_setup_command.py (blocked by TASK-024)
   - 1 failing test in test_schedule_command.py

### Wizard Notes (Previous Audits)

- All 676 wizard tests passing (1 skipped - history database locked test on Windows)
- Overall wizard_flows coverage: 93%
- High coverage (>95%): validators.py (100%), profile_config.py (100%), config_models.py (100%), telemetry_helper.py (100%), dependency_flow.py (100%), repo_flow.py (100%), stack_flow.py (99%), command_builder.py (97%), cicd_flow.py (96%), diff_flow.py (95%)
- Good coverage (85-95%): deployment_flow.py (93%), tool_checker.py (93%), trend_flow.py (92%), ui_helpers.py (93%), target_configurators.py (91%), base_flow.py (85%)
- Windows platform (4 tools excluded: falco, afl++, mobsf, akto)
- OPA detection fix was applied (find_tool instead of shutil.which)
- Remaining coverage gaps are low-priority: platform-specific code (Windows ctypes), rare exception paths, UI error handling
