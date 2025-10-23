# Phase 4 Refactoring - Detailed Implementation Plan

**Status:** Ready for Implementation (Fresh Session Recommended)
**Estimated Total Time:** 8-12 hours
**Completion Date:** TBD

## Overview

Phase 4 addresses the two most complex and time-consuming refactoring tasks identified by the code-quality-auditor agent. These are the highest-priority blockers for v0.7.0 release that require comprehensive architectural improvements.

**Important:** This phase should be completed in a fresh session due to:
- High complexity requiring full context window
- Extensive testing and validation needed
- Multiple file changes with interdependencies
- Risk of circular imports requiring careful planning

---

## HP-001: Refactor cmd_scan() - Reduce Cyclomatic Complexity

**File:** `scripts/cli/jmo.py`
**Current Location:** Line 661-1490 (830 lines)
**Current Metrics:**
- Cyclomatic Complexity: 39 (Grade F - "Unmaintainable")
- Lines of Code: 830 lines in single function
- Maintainability Index: Low

**Target Metrics:**
- Cyclomatic Complexity: <15 per function (Grade A/B)
- Lines of Code: <200 lines per function
- Maintainability Index: 20+

**Estimated Time:** 4-6 hours

---

### Problem Analysis

The `cmd_scan()` function currently handles:
1. **Configuration loading** (50+ lines)
2. **Environment setup** (40+ lines)
3. **Telemetry preparation** (30+ lines)
4. **6 different target type scanners** (400+ lines):
   - Repository scanning (local repos, repos-dir, targets, TSV)
   - Container image scanning
   - IaC file scanning
   - Web URL scanning (DAST)
   - GitLab repository scanning
   - Kubernetes cluster scanning
5. **Job submission** (ThreadPoolExecutor management, 80+ lines)
6. **Result collection** (60+ lines)
7. **Logging and error handling** (throughout)

**Key Complexity Drivers:**
- 6 nested loops for different target types
- Multiple conditional branches for each target type
- ThreadPoolExecutor management scattered throughout
- Duplicated error handling patterns
- Mixed concerns (setup, execution, collection)

---

### Proposed Refactoring Strategy

#### Extract 4 Major Helper Functions

```python
def _setup_scan_environment(args, cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Setup scan environment and return configuration.

    Responsibilities:
    - Load jmo.yml config
    - Resolve profile settings
    - Setup results directory
    - Initialize logging
    - Validate tool availability

    Args:
        args: Parsed command-line arguments
        cfg: Initial config dict

    Returns:
        Dict with:
        - results_dir: Path
        - tools: List[str]
        - max_workers: int
        - timeout: int
        - retries: int
        - per_tool: Dict
        - ok_rcs: Dict

    Raises:
        SystemExit: If critical config/setup fails
    """
    pass


def _prepare_telemetry_data(args, cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Prepare telemetry metadata for scan submission.

    Responsibilities:
    - Check if telemetry enabled
    - Gather system metadata
    - Collect target info
    - Build telemetry payload

    Args:
        args: Parsed command-line arguments
        cfg: Scan configuration

    Returns:
        Telemetry dict if enabled, None otherwise
    """
    pass


def _submit_scan_jobs(
    args,
    cfg: Dict[str, Any],
    results_dir: Path,
    tools: List[str],
    max_workers: int,
    timeout: int,
    retries: int,
    per_tool: Dict,
    ok_rcs: Dict
) -> List[Future]:
    """
    Submit all scan jobs to ThreadPoolExecutor.

    Responsibilities:
    - Detect all 6 target types from args
    - Submit parallel scan jobs for:
      * Repositories (repo, repos-dir, targets, TSV)
      * Container images
      * IaC files
      * Web URLs
      * GitLab repositories
      * Kubernetes clusters
    - Return list of futures for result collection

    Args:
        args: Parsed command-line arguments
        cfg: Scan configuration
        results_dir: Base results directory
        tools: List of tools to run
        max_workers: Thread pool size
        timeout: Per-tool timeout
        retries: Retry count for flaky tools
        per_tool: Per-tool config overrides
        ok_rcs: Acceptable return codes per tool

    Returns:
        List of Future objects representing submitted jobs
    """
    pass


def _collect_scan_results(
    futures: List[Future],
    target_type: str
) -> Dict[str, Dict[str, bool]]:
    """
    Collect results from completed scan jobs.

    Responsibilities:
    - Wait for all futures to complete
    - Log success/failure for each target
    - Aggregate overall status
    - Handle exceptions gracefully

    Args:
        futures: List of Future objects from executor
        target_type: Type of targets being scanned (for logging)

    Returns:
        Dict mapping target names to tool status dicts
    """
    pass
```

#### Simplified cmd_scan() Structure

After refactoring, `cmd_scan()` should look like:

```python
def cmd_scan(args) -> int:
    """Run configured tools on specified targets and write JSON outputs."""
    # 1. Setup environment (30-40 lines)
    cfg = _setup_scan_environment(args, {})
    results_dir = cfg["results_dir"]
    tools = cfg["tools"]
    max_workers = cfg["max_workers"]
    timeout = cfg["timeout"]
    retries = cfg["retries"]
    per_tool = cfg["per_tool"]
    ok_rcs = cfg["ok_rcs"]

    # 2. Prepare telemetry (10-15 lines)
    telemetry_data = _prepare_telemetry_data(args, cfg)
    if telemetry_data:
        _submit_telemetry(telemetry_data)

    # 3. Submit all scan jobs (10-15 lines)
    futures = _submit_scan_jobs(
        args, cfg, results_dir, tools, max_workers,
        timeout, retries, per_tool, ok_rcs
    )

    # 4. Collect results (10-15 lines)
    all_results = _collect_scan_results(futures, "all-targets")

    # 5. Log summary and exit (20-30 lines)
    total_targets = len(all_results)
    total_tools = sum(len(statuses) for statuses in all_results.values())
    successful = sum(
        1 for statuses in all_results.values()
        for ok in statuses.values() if ok
    )

    _log(args, "INFO", f"Scan complete: {successful}/{total_tools} tool runs succeeded across {total_targets} targets")
    return 0
```

**Target Lines:** 80-120 lines (vs. current 830)

---

### Implementation Steps

#### Step 1: Extract _setup_scan_environment() (60-90 min)

1. **Identify all environment setup code** (lines 661-750)
   - Config loading
   - Profile resolution
   - Results directory creation
   - Logging setup
   - Tool validation

2. **Create new function** with clear return type

3. **Test with existing integration tests**
   ```bash
   pytest tests/integration/test_cli_scan_ci.py -v
   pytest tests/integration/test_cli_profiles.py -v
   ```

4. **Verify no regressions**

#### Step 2: Extract _prepare_telemetry_data() (45-60 min)

1. **Identify telemetry preparation code** (lines 780-830)
   - Telemetry check
   - Metadata gathering
   - Payload construction

2. **Create new function** with Optional return type

3. **Test with telemetry tests**
   ```bash
   pytest tests/unit/test_telemetry.py -v
   ```

4. **Verify telemetry still works**

#### Step 3: Extract _submit_scan_jobs() (2-3 hours)

**This is the most complex step.**

1. **Identify all job submission code** (lines 850-1350)
   - Repository scanning loops
   - Container image scanning
   - IaC file scanning
   - Web URL scanning
   - GitLab scanning
   - Kubernetes scanning
   - ThreadPoolExecutor management

2. **Create new function** that returns List[Future]

3. **Important: Keep existing helper functions** (don't refactor these):
   - `_iter_repos()` - Repository detection
   - `_iter_images()` - Image detection
   - `_iter_iac_files()` - IaC file detection
   - `_iter_urls()` - URL detection
   - `_iter_gitlab_repos()` - GitLab repo detection
   - `_iter_k8s_targets()` - Kubernetes target detection
   - `job_repo()` - Repository scan job
   - `job_image()` - Image scan job
   - `job_iac()` - IaC scan job
   - `job_url()` - URL scan job
   - `job_gitlab()` - GitLab scan job
   - `job_k8s()` - Kubernetes scan job

4. **Structure of _submit_scan_jobs()**:
   ```python
   def _submit_scan_jobs(...) -> List[Future]:
       futures = []

       # Create executor
       with ThreadPoolExecutor(max_workers=max_workers) as ex:
           # Submit repo jobs
           for repo in _iter_repos(args):
               futures.append(ex.submit(job_repo, repo, ...))

           # Submit image jobs
           for image in _iter_images(args):
               futures.append(ex.submit(job_image, image, ...))

           # ... other target types

       return futures
   ```

5. **Test with multi-target tests**
   ```bash
   pytest tests/integration/test_multi_target_scanning.py -v
   pytest tests/integration/test_cli_scan_tools.py -v
   ```

6. **Verify all 6 target types still work**

#### Step 4: Extract _collect_scan_results() (45-60 min)

1. **Identify result collection code** (lines 1370-1450)
   - Future completion waiting
   - Result logging
   - Status aggregation

2. **Create new function** with clear Dict return type

3. **Test with existing integration tests**
   ```bash
   pytest tests/integration/test_cli_scan_ci.py -v
   ```

4. **Verify result collection works**

#### Step 5: Simplify cmd_scan() (30-45 min)

1. **Replace extracted code** with function calls

2. **Add clear comments** for each phase

3. **Test comprehensive suite**
   ```bash
   pytest tests/integration/ -v
   pytest tests/cli/ -v
   ```

4. **Verify overall flow works**

#### Step 6: Final Validation (30-45 min)

1. **Run full test suite**
   ```bash
   make test
   ```

2. **Verify coverage maintained** (≥85%)

3. **Run linting**
   ```bash
   make lint
   ```

4. **Manual smoke test** with wizard
   ```bash
   jmotools wizard --yes
   ```

---

### Testing Strategy

**Unit Tests to Update:**
- `tests/cli/test_jmo_scan.py` - May need updates if function signatures change
- `tests/unit/test_telemetry.py` - Update if telemetry extraction changes behavior

**Integration Tests to Run:**
- `tests/integration/test_cli_scan_ci.py` - Core scan functionality
- `tests/integration/test_cli_profiles.py` - Profile-based scanning
- `tests/integration/test_multi_target_scanning.py` - All 6 target types
- `tests/integration/test_cli_scan_tools.py` - Tool execution

**Smoke Tests:**
- Run wizard with all target types
- Run manual scan with each target type
- Run CI command with multi-target

---

### Risks and Mitigation

| Risk | Mitigation |
|------|------------|
| **ThreadPoolExecutor context manager changes behavior** | Keep executor creation in _submit_scan_jobs(), test thoroughly |
| **Circular imports if helpers moved to separate module** | Keep all functions in jmo.py for now |
| **Tests expect specific error messages** | Preserve all user-facing log messages |
| **Per-tool config not passed correctly** | Test each tool individually |
| **TSV mode breaks** | Add specific test for TSV scanning |

---

### Success Criteria

✅ **Metrics:**
- cmd_scan() CC reduced from 39 to <15
- cmd_scan() reduced from 830 to <150 lines
- All 4 helper functions CC <10
- Maintainability Index >20

✅ **Functionality:**
- All 6 target types still work
- Profiles still work (fast/balanced/deep)
- Per-tool overrides still work
- Telemetry still works
- TSV mode still works

✅ **Quality:**
- All tests pass (≥1224 tests)
- Coverage maintained (≥85%)
- No linting errors
- No new exceptions/warnings

---

## HP-003: Improve wizard.py Maintainability

**File:** `scripts/cli/wizard.py`
**Current Location:** Entire file (1502 lines after HP-002)
**Current Metrics:**
- Maintainability Index: 2.11 (Grade F - "Extremely Unmaintainable")
- Lines of Code: 1502 lines
- Functions: 35+ functions in single file
- Complexity: Multiple high-CC functions

**Target Metrics:**
- Maintainability Index: 15-20 (Grade B)
- Lines of Code: <500 per module
- File Count: 4-5 modular files
- Complexity: All functions CC <15

**Estimated Time:** 4-6 hours

---

### Problem Analysis

The wizard.py file currently contains:
1. **Configuration management** (dataclasses, config building)
2. **Target detection** (repo/image/IaC/URL/GitLab/K8s detection)
3. **User interface** (interactive prompts, input validation)
4. **Command generation** (Docker/native command building)
5. **Artifact generation** (Makefile, shell scripts, GitHub Actions)
6. **Execution logic** (scan execution, result opening)
7. **Utility functions** (path validation, file type detection)

**Key Complexity Drivers:**
- Single 1502-line file with mixed concerns
- 35+ functions without clear organization
- Circular dependencies between functions
- Difficult to test individual components
- Hard to find specific functionality

---

### Proposed Refactoring Strategy

#### Split into 5 Modular Files

```text
scripts/cli/
├── wizard.py                    # Main entry point + orchestration (200-250 lines)
├── wizard_config.py             # Config dataclasses and builders (250-300 lines)
├── wizard_targets.py            # Target detection and validation (300-350 lines)
├── wizard_ui.py                 # User interaction and prompts (400-450 lines)
└── wizard_generators.py         # Command and artifact generation (350-400 lines)
```

---

### Module Design

#### 1. wizard_config.py - Configuration Management

**Purpose:** Configuration dataclasses and builders

**Contents:**
```python
from dataclasses import dataclass
from typing import Optional

@dataclass
class TargetConfig:
    """Configuration for scan target."""
    type: str  # "repo", "image", "iac", "url", "gitlab", "k8s"
    # ... existing fields

@dataclass
class WizardConfig:
    """Complete wizard configuration."""
    profile: str
    use_docker: bool
    target: TargetConfig
    # ... existing fields

class ConfigBuilder:
    """Builder pattern for constructing WizardConfig."""

    def __init__(self):
        self._config = {}

    def with_profile(self, profile: str) -> 'ConfigBuilder':
        self._config['profile'] = profile
        return self

    def with_target(self, target: TargetConfig) -> 'ConfigBuilder':
        self._config['target'] = target
        return self

    # ... other builder methods

    def build(self) -> WizardConfig:
        """Build final config with validation."""
        # Validate required fields
        # Apply defaults
        # Return WizardConfig instance
        pass
```

**Lines:** 250-300
**Complexity:** Low (mostly dataclasses and simple builders)

---

#### 2. wizard_targets.py - Target Detection and Validation

**Purpose:** Target detection, path validation, file type inference

**Contents:**
```python
from pathlib import Path
from typing import Optional, List

def validate_path(path_str: str, must_exist: bool = True) -> Optional[Path]:
    """Validate and resolve path."""
    pass

def infer_file_type(file_path: Path) -> str:
    """Infer file type from path and contents."""
    pass

def detect_targets_in_directory(directory: Path) -> List[str]:
    """Detect scan targets in directory."""
    pass

def validate_docker_image(image: str) -> bool:
    """Validate Docker image format."""
    pass

def validate_url(url: str) -> bool:
    """Validate URL format."""
    pass

def validate_gitlab_repo(repo: str) -> bool:
    """Validate GitLab repo format."""
    pass

def validate_k8s_context(context: str) -> bool:
    """Validate Kubernetes context."""
    pass
```

**Lines:** 300-350
**Complexity:** Medium (path handling, file I/O)

**Key Functions to Move:**
- `_validate_path()` (current line 244)
- `infer_file_type()` (current line 260)
- All path validation helpers

---

#### 3. wizard_ui.py - User Interaction

**Purpose:** Interactive prompts, input validation, user feedback

**Contents:**
```python
from typing import Optional, List

class WizardUI:
    """User interface for interactive wizard."""

    def __init__(self, non_interactive: bool = False):
        self.non_interactive = non_interactive

    def prompt_profile(self) -> str:
        """Prompt user to select profile."""
        if self.non_interactive:
            return "balanced"  # Default

        print("Select scan profile:")
        print("1. fast (3 tools, 5-8 min)")
        print("2. balanced (8 tools, 15-20 min)")
        print("3. deep (12 tools, 30-60 min)")

        choice = input("Enter choice [1-3] (default: 2): ").strip()
        # ... validation
        pass

    def prompt_target_type(self) -> str:
        """Prompt user to select target type."""
        pass

    def prompt_repo_mode(self) -> str:
        """Prompt user to select repository mode."""
        pass

    def prompt_docker_mode(self) -> bool:
        """Prompt user to select Docker vs native."""
        pass

    def prompt_execution(self) -> str:
        """Prompt user to select execution mode."""
        pass

    def show_config_summary(self, config: WizardConfig) -> None:
        """Display configuration summary."""
        pass

    def confirm_execution(self) -> bool:
        """Confirm execution with user."""
        pass
```

**Lines:** 400-450
**Complexity:** Low-Medium (mostly input/output)

**Key Functions to Move:**
- `_prompt_*()` functions (current lines 450-900)
- `_show_config_summary()` (current line 950)
- All interactive prompt logic

---

#### 4. wizard_generators.py - Command and Artifact Generation

**Purpose:** Command generation, Makefile, shell scripts, GitHub Actions

**Contents:**
```python
from typing import List

def build_command_parts(config: WizardConfig) -> List[str]:
    """Build command parts as list (shared helper)."""
    # Moved from wizard.py (current line 1050)
    pass

def generate_command(config: WizardConfig) -> str:
    """Generate command string for display."""
    return " ".join(build_command_parts(config))

def generate_command_list(config: WizardConfig) -> List[str]:
    """Generate command list for subprocess execution."""
    return build_command_parts(config)

def generate_makefile(config: WizardConfig) -> str:
    """Generate Makefile target."""
    pass

def generate_shell_script(config: WizardConfig) -> str:
    """Generate standalone shell script."""
    pass

def generate_github_actions(config: WizardConfig) -> str:
    """Generate GitHub Actions workflow."""
    pass

def emit_artifact(artifact_type: str, config: WizardConfig, output_path: Path) -> None:
    """Emit artifact to file."""
    pass
```

**Lines:** 350-400
**Complexity:** Medium (string generation, templating)

**Key Functions to Move:**
- `_build_command_parts()` (current line 1050)
- `generate_command()` (current line 1150)
- `generate_command_list()` (current line 1160)
- All artifact generation functions

---

#### 5. wizard.py - Main Orchestration

**Purpose:** Entry point, high-level workflow, orchestration

**Contents:**
```python
from wizard_config import WizardConfig, ConfigBuilder
from wizard_targets import validate_path, infer_file_type
from wizard_ui import WizardUI
from wizard_generators import generate_command, generate_command_list

class WizardOrchestrator:
    """Orchestrates the wizard workflow."""

    def __init__(self, args):
        self.args = args
        self.ui = WizardUI(non_interactive=args.yes)
        self.builder = ConfigBuilder()

    def run(self) -> int:
        """Run complete wizard workflow."""
        # 1. Gather configuration
        config = self._gather_config()

        # 2. Show summary
        self.ui.show_config_summary(config)

        # 3. Execute or emit
        return self._execute_or_emit(config)

    def _gather_config(self) -> WizardConfig:
        """Gather configuration from user."""
        # Prompt for profile
        profile = self.ui.prompt_profile()
        self.builder.with_profile(profile)

        # Prompt for target
        target = self._gather_target_config()
        self.builder.with_target(target)

        # Prompt for Docker mode
        use_docker = self.ui.prompt_docker_mode()
        self.builder.with_docker(use_docker)

        # Build final config
        return self.builder.build()

    def _gather_target_config(self) -> TargetConfig:
        """Gather target configuration."""
        target_type = self.ui.prompt_target_type()
        # ... specific target prompts
        pass

    def _execute_or_emit(self, config: WizardConfig) -> int:
        """Execute scan or emit artifact."""
        if self.args.emit_make_target:
            self._emit_makefile(config)
            return 0
        elif self.args.emit_script:
            self._emit_script(config)
            return 0
        elif self.args.emit_gha:
            self._emit_github_actions(config)
            return 0
        else:
            return self._execute_scan(config)

def main() -> int:
    """Main entry point for wizard."""
    args = parse_args()
    orchestrator = WizardOrchestrator(args)
    return orchestrator.run()
```

**Lines:** 200-250
**Complexity:** Low (orchestration only, delegates to helpers)

---

### Implementation Steps

#### Step 1: Create wizard_config.py (60-90 min)

1. **Create new file** `scripts/cli/wizard_config.py`

2. **Move dataclasses** from wizard.py:
   - `TargetConfig` (line 50)
   - `WizardConfig` (line 100)

3. **Create ConfigBuilder class** for cleaner config construction

4. **Update imports** in wizard.py

5. **Test**
   ```bash
   pytest tests/cli/test_wizard.py::test_config_dataclasses -v
   ```

#### Step 2: Create wizard_targets.py (60-90 min)

1. **Create new file** `scripts/cli/wizard_targets.py`

2. **Move functions** from wizard.py:
   - `_validate_path()` (line 244)
   - `infer_file_type()` (line 260)
   - All path validation helpers

3. **Update imports** in wizard.py

4. **Test**
   ```bash
   pytest tests/cli/test_wizard.py::test_path_validation -v
   pytest tests/cli/test_wizard.py::test_file_type_inference -v
   ```

#### Step 3: Create wizard_generators.py (90-120 min)

1. **Create new file** `scripts/cli/wizard_generators.py`

2. **Move functions** from wizard.py:
   - `_build_command_parts()` (line 1050)
   - `generate_command()` (line 1150)
   - `generate_command_list()` (line 1160)
   - All artifact generation functions

3. **Update imports** in wizard.py

4. **Test**
   ```bash
   pytest tests/cli/test_wizard.py::test_generate_command -v
   pytest tests/cli/test_wizard.py::test_generate_command_list -v
   ```

#### Step 4: Create wizard_ui.py (90-120 min)

1. **Create new file** `scripts/cli/wizard_ui.py`

2. **Move functions** from wizard.py:
   - All `_prompt_*()` functions
   - `_show_config_summary()`
   - Interactive input logic

3. **Create WizardUI class** to encapsulate prompts

4. **Update imports** in wizard.py

5. **Test**
   ```bash
   pytest tests/cli/test_wizard.py::test_non_interactive_mode -v
   ```

#### Step 5: Refactor wizard.py to Orchestrator (60-90 min)

1. **Create WizardOrchestrator class** in wizard.py

2. **Simplify main()** to just instantiate orchestrator

3. **Update all function calls** to use new modules

4. **Test comprehensive suite**
   ```bash
   pytest tests/cli/test_wizard.py -v
   ```

#### Step 6: Update Tests (45-60 min)

1. **Update test imports** to use new modules

2. **Add module-specific tests**:
   - `tests/cli/test_wizard_config.py` - Config builder tests
   - `tests/cli/test_wizard_targets.py` - Target validation tests
   - `tests/cli/test_wizard_ui.py` - UI prompt tests
   - `tests/cli/test_wizard_generators.py` - Generator tests

3. **Ensure comprehensive coverage** (≥85% per module)

#### Step 7: Final Validation (30-45 min)

1. **Run full test suite**
   ```bash
   make test
   ```

2. **Verify wizard still works**
   ```bash
   jmotools wizard --yes
   jmotools wizard  # Interactive mode
   ```

3. **Run linting**
   ```bash
   make lint
   ```

4. **Check maintainability**
   - wizard.py: MI should increase from 2.11 to 15-20
   - Each module: MI >20

---

### Testing Strategy

**Unit Tests to Create:**
- `tests/cli/test_wizard_config.py` - ConfigBuilder, dataclass validation
- `tests/cli/test_wizard_targets.py` - Path validation, file type detection
- `tests/cli/test_wizard_ui.py` - Prompt logic (mocked input)
- `tests/cli/test_wizard_generators.py` - Command generation, artifacts

**Integration Tests to Update:**
- `tests/cli/test_wizard.py` - End-to-end wizard flows
- Update imports to use new modules

**Smoke Tests:**
- Interactive wizard with manual input
- Non-interactive wizard (--yes)
- Artifact generation (--emit-make-target, --emit-script, --emit-gha)

---

### Risks and Mitigation

| Risk | Mitigation |
|------|------------|
| **Circular imports between modules** | Design clear dependency hierarchy: config → targets → ui/generators → orchestrator |
| **Tests break due to import changes** | Update all imports systematically, test incrementally |
| **Non-interactive mode breaks** | Test --yes flag extensively |
| **Artifact generation breaks** | Test all emit modes individually |

---

### Success Criteria

✅ **Metrics:**
- wizard.py MI increased from 2.11 to 15-20
- wizard.py reduced from 1502 to <250 lines
- All 5 modules CC <10 per function
- All modules MI >20

✅ **Functionality:**
- Interactive mode still works
- Non-interactive mode (--yes) still works
- All 6 target types still work
- Artifact generation (Makefile, script, GHA) still works
- Docker mode still works
- Native mode still works

✅ **Quality:**
- All tests pass (≥60 wizard tests)
- Coverage maintained (≥85% per module)
- No linting errors
- No circular imports

---

## Phase 4 Summary

| Task | Complexity | Time Estimate | Key Risk |
|------|------------|---------------|----------|
| HP-001 (cmd_scan refactoring) | Very High | 4-6 hours | ThreadPoolExecutor behavior changes |
| HP-003 (wizard.py modularization) | High | 4-6 hours | Circular imports |
| **Total** | **Very High** | **8-12 hours** | **Session context window management** |

---

## Recommended Execution Plan

### Session 1: HP-001 (cmd_scan refactoring)

**Duration:** 4-6 hours
**Focus:** Single complex task with full context

1. Extract _setup_scan_environment()
2. Extract _prepare_telemetry_data()
3. Extract _submit_scan_jobs()
4. Extract _collect_scan_results()
5. Simplify cmd_scan()
6. Full test suite validation

**Checkpoint:** All integration tests pass, coverage ≥85%

---

### Session 2: HP-003 (wizard.py modularization)

**Duration:** 4-6 hours
**Focus:** Architectural reorganization

1. Create wizard_config.py
2. Create wizard_targets.py
3. Create wizard_generators.py
4. Create wizard_ui.py
5. Refactor wizard.py to orchestrator
6. Update tests
7. Full validation

**Checkpoint:** All wizard tests pass, MI >15

---

## Completion Criteria

Phase 4 is complete when:

✅ **HP-001:** cmd_scan() CC <15, all integration tests pass
✅ **HP-003:** wizard.py MI >15, all modules MI >20, all wizard tests pass
✅ **Overall:** All 1224+ tests pass, coverage ≥85%, no linting errors

---

## Post-Phase 4 Actions

After completing Phase 4:

1. **Update CHANGELOG.md** with refactoring improvements
2. **Update ROADMAP.md** to mark code quality improvements complete
3. **Run full release checklist** (docs/RELEASE.md)
4. **Tag v0.7.0 release**
5. **Celebrate!** 🎉

---

## Notes for Implementation

- **Session Management:** Each task requires substantial context - use fresh sessions
- **Incremental Testing:** Test after each extraction step
- **Preserve Behavior:** No functional changes, only structural improvements
- **Documentation:** Update docstrings with new function responsibilities
- **Git Commits:** Small, atomic commits for easy rollback if needed

---

**Document Version:** 1.0
**Last Updated:** 2025-10-23
**Status:** Ready for Implementation
