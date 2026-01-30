# Implementation Plan - CLI Testing

This file is shared state between Ralph Loop iterations. Claude reads it to find work and updates it to record progress.

---

## Task Templates

### BUG Task
```
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
```
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
```
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
| Bug | 0 | 2 | 0 | 2 |
| Coverage | 0 | 0 | 0 | 0 |
| Security | 0 | 0 | - | 0 |
| **Total** | **0** | **2** | **0** | **2** |

---

## Current Tasks

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
```
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
```
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
```
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
```
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
