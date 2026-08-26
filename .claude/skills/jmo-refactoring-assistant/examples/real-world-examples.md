# Real-World Refactoring Examples

Examples from actual JMo Security refactoring tasks with before/after metrics and lessons learned.

---

## Example 1: Split compliance_mapper.py (Task 3.5) - COMPLETED

**Goal:** Extract 890 lines of framework data constants

**Command:**

```bash
# This is conceptual - skill was applied manually following methodology
# Target: scripts/core/compliance_mapper.py (1,278 lines)
# Refactor type: split_file (data extraction)
```

**Actual Results:**

```text
Analyzing scripts/core/compliance_mapper.py...

Metrics Before:
- Total lines: 1,278
- Framework data constants: 890 lines (lines 29-919)
- Mapping functions: 352 lines (lines 926-1278)
- Maintainability: Mixed data and logic

Refactoring Strategy:
1. Create compliance_frameworks.py with all 6 framework constants
2. Update compliance_mapper.py to import from new module
3. Remove 890 lines of data from compliance_mapper.py
4. Preserve all 11 mapping functions

Files Created:
- scripts/core/compliance_frameworks.py (912 lines)
  - CWE_TOP_25_2024
  - CWE_TO_OWASP_TOP10_2021
  - TOOL_RULE_TO_OWASP_TOP10_2021
  - CIS_CONTROLS_V8_1
  - NIST_CSF_2_0
  - CWE_TO_NIST_CSF_2_0
  - PCI_DSS_4_0
  - CWE_TO_PCI_DSS_4_0
  - MITRE_ATTACK
  - CWE_TO_MITRE_ATTACK

Files Modified:
- scripts/core/compliance_mapper.py (1,278 -> 399 lines)
  - Added imports from compliance_frameworks
  - Removed all framework data
  - Preserved all 11 mapping functions
  - Added refactoring note in docstring

Implementation Details:
- No circular imports (pure data module)
- Clean separation: data vs logic
- Zero function signature changes
- All existing imports still work

Running tests...
- 89/89 compliance tests passing
- Coverage: Maintained at 100%

Metrics After:
- compliance_mapper.py: 1,278 -> 399 lines (69% reduction)
- compliance_frameworks.py: 912 lines (new module)
- Total: 1,311 lines (+33 due to imports/docstrings)
- Maintainability: Excellent (data separate from logic)
- Circular imports: Zero

Refactoring complete!
```

**Lessons Learned:**

1. Data extraction is the cleanest refactoring (no circular import risk)
2. Total line count may increase slightly (imports/docstrings) but maintainability improves
3. Run `ruff check --fix` to remove unused imports automatically
4. Keep both modules in same directory for clean relative imports

---

## Example 2: Extract wizard.py generators (Task 3.6) - COMPLETED

**Goal:** Extract 3 artifact generator functions (134 lines)

**Command:**

```bash
# This is conceptual - skill was applied manually following methodology
# Target: scripts/cli/wizard.py (959 lines)
# Refactor type: extract_function
```

**Actual Results:**

```text
Analyzing scripts/cli/wizard.py...

Metrics Before:
- Total lines: 959
- Target functions:
  - generate_makefile_target() (10 lines)
  - generate_shell_script() (11 lines)
  - generate_github_actions() (113 lines)
- Total extracted: 134 lines

Circular Import Risk Detected:
- wizard_generators needs: WizardConfig, PROFILES
- wizard needs: generate_*() functions
- Risk: Circular import if using direct imports

Refactoring Strategy:
1. Create wizard_generators.py with 3 generator functions
2. Use TYPE_CHECKING pattern for WizardConfig type hint
3. Use parameter injection for PROFILES dict
4. Update run_wizard() to pass dependencies
5. Update 4 test functions with new signatures

Files Created:
- scripts/cli/wizard_generators.py (180 lines)
  - TYPE_CHECKING import for WizardConfig
  - generate_makefile_target(config, command)
  - generate_shell_script(config, command)
  - generate_github_actions(config, profiles)

Files Modified:
- scripts/cli/wizard.py (959 -> 825 lines)
  - Added imports from wizard_generators
  - Removed 3 generator functions
  - Updated 3 call sites to pass parameters
- tests/cli/test_wizard.py
  - Split imports between wizard and wizard_generators
  - Updated 4 test functions to pass parameters

Implementation Details:
- Circular import avoided with TYPE_CHECKING
- Parameter injection used (command, profiles)
- Type hints preserved (mypy/pyright still work)
- Runtime types use Any to avoid circular import

Function Signature Changes:
# BEFORE
generate_makefile_target(config: WizardConfig) -> str
generate_github_actions(config: WizardConfig) -> str

# AFTER
generate_makefile_target(config: Any, command: str) -> str
generate_github_actions(config: Any, profiles: Dict[str, Any]) -> str

Call Site Updates (3 locations):
# BEFORE
makefile = generate_makefile_target(config)

# AFTER
command = generate_command(config)  # Generate dependency
makefile = generate_makefile_target(config, command)  # Inject

Running tests...
- 61/63 wizard tests passing
- 2 pre-existing failures (unrelated to refactoring)
- Coverage: Maintained

Metrics After:
- wizard.py: 959 -> 825 lines (14% reduction)
- wizard_generators.py: 180 lines (new module)
- Total: 1,005 lines (+46 due to imports/signatures)
- Circular imports: Zero
- Test updates: 4 functions + import split

Refactoring complete!
```

**Lessons Learned:**

1. Function extraction risks circular imports (unlike data extraction)
2. TYPE_CHECKING + parameter injection pattern works perfectly
3. Must update ALL call sites (source + tests)
4. Test imports must be split between old and new modules
5. Type checkers happy, runtime happy, no circular imports
6. 14% reduction is still valuable (better organization)
