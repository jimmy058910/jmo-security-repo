---
name: jmo-refactoring-assistant
description: Automate complex refactoring tasks like function decomposition, pattern migration, and file splitting while preserving test coverage. Use for monolith decomposition or design pattern migration.
argument-hint: <refactoring-type>
user-invocable: true
context: fork
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

## Execution

Refactoring target: **$ARGUMENTS**

---

## Purpose

Systematically decompose monolithic functions, migrate to design patterns, and split oversized files while preserving test coverage and preventing regressions.

This skill helps you refactor the JMo Security codebase by:

1. **Decomposing monolithic functions** (e.g., cmd_scan: 1,553 lines, CC 252)
2. **Migrating to design patterns** (e.g., the Strategy-pattern installers in `scripts/cli/installers/`)
3. **Splitting oversized files** (e.g., jmo.py: 2,456 lines -> 600 lines)
4. **Preserving test coverage** and preventing regressions
5. **Avoiding circular dependencies** with proven patterns

---

**Approach:** Preserve behavior exactly. Every refactoring must have a test that passes before and after.

## When to Use This Skill

Use when code exhibits high cyclomatic complexity (CC >10), excessive line count (functions >50 lines, files >500 lines), code duplication, or SRP violations.

**Primary Use Cases:**

| ID | Target | Status |
|----|--------|--------|
| CRITICAL-001 | cmd_scan() decomposition (ToolRunner, ScanOrchestrator) | Remaining |
| CRITICAL-002 | ~~BaseAdapter pattern migration (14 adapters)~~ | **Withdrawn** — `BaseAdapter` was subclassed by nothing and implemented a *different* contract (dicts, its own fingerprinting) from the live `@adapter_plugin` + `AdapterPlugin.parse()` one. Deleted; migrating onto it would have produced adapters the plugin loader cannot register |
| HIGH-002a | compliance_mapper.py (1,278 -> 399 lines) | COMPLETED |
| HIGH-002b | wizard.py (959 -> 825 lines) | COMPLETED |
| HIGH-001 | Embedded 777-line job() function extraction | Remaining |

---

## How It Works

The skill performs refactoring in 6 phases:

### Phase 1: Analysis

- Read target file(s), identify complexity hotspots (high CC functions)
- Detect code duplication patterns and SRP violations
- Map dependencies (imports, function calls, tests)
- Check for circular import risks

### Phase 2: Design

- Propose refactoring strategy based on target type
- Generate new file structure, class/function signatures with proper typing
- Plan parameter injection strategy to avoid circular imports
- Plan test migration strategy

### Phase 3: Implementation

- Extract classes/functions to new files
- Use TYPE_CHECKING for type hints without runtime imports
- Refactor function signatures (add dependency injection parameters)
- Preserve existing behavior; maintain backward compatibility

### Phase 4: Test Migration

- Update existing tests to use new structure
- Split test imports between old and new modules
- Update test function calls with new parameters
- Verify coverage doesn't decrease

> Full test migration patterns: [references/test-migration-patterns.md](references/test-migration-patterns.md)

### Phase 5: Validation

- Run full test suite (pytest), check coverage (must be >= current)
- Verify no lint/type errors (ruff + black)
- Fix unused imports (common after extraction)

### Phase 6: Documentation

- Update module docstrings with refactoring notes
- Add cross-references in comments
- Document parameter injection rationale

---

## Refactoring Type Decision Tree

**Use this flowchart to choose the right refactoring type:**

```text
                What are you refactoring?
                         |
               Data vs Functions?
                    |           |
                [Data]      [Functions]
                    |           |
              split_file   extract_function
                    |           |
              Extract to   Extract to
              *_constants  *_helpers.py
              *_frameworks *_generators
                    |           |
              No circular   Risk of circular
              imports!       imports!
              Clean          Use TYPE_CHECKING
              separation     + parameter injection
```

**Quick Reference:**

| Situation | Refactoring Type | Example |
|-----------|-----------------|---------|
| 890+ lines of constants/data | `split_file` | compliance_frameworks.py |
| 3-5 small related functions | `extract_function` | wizard_generators.py |
| 1,500+ line monolithic function | `extract_monolith` | cmd_scan() (future) |
| 14 adapters with duplicate code | shared helpers in `adapters/common.py` | `safe_load_json_file` / `safe_load_ndjson_file` |
| 2,400+ line file | `split_file` (multi-module) | jmo.py (future) |

---

## Circular Dependency Resolution

### Problem

When extracting functions, the new module and source module can form a circular import if both directly import from each other.

### Solution 1: TYPE_CHECKING Pattern (Recommended)

```python
# scripts/cli/wizard_generators.py
from __future__ import annotations
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from scripts.cli.wizard import WizardConfig  # Only used by type checkers

def generate_github_actions(config: Any, profiles: Dict[str, Any]) -> str:
    profile_info = profiles[config.profile]
    ...
```

### Solution 2: Parameter Injection (Recommended)

Pass dependencies as parameters instead of importing them:

```python
# scripts/cli/wizard_generators.py
def generate_github_actions(config: Any, profiles: Dict[str, Any]) -> str:
    ...  # No import needed - caller passes PROFILES dict

# scripts/cli/wizard.py
from scripts.cli.wizard_generators import generate_github_actions
workflow = generate_github_actions(config, PROFILES)  # Inject dependency
```

### Solution 3: Move Shared Data (Use Sparingly)

Create a third module (`wizard_config.py`) for shared data when many constants are needed by both sides.

### Decision Matrix

| Scenario | Solution | Rationale |
|----------|----------|-----------|
| Type hints only | TYPE_CHECKING | No runtime dependency needed |
| Small number of dependencies | Parameter Injection | Explicit, testable |
| Many shared constants | Move to shared module | Reduces duplication |
| Complex circular web | Redesign module structure | Neither pattern fixes bad design |

---

## Import Update Checklist

After extracting code, update imports systematically:

### 1. Update Source File

```python
# Add imports from new module, remove extracted function bodies
from scripts.cli.wizard_generators import (
    generate_github_actions,
    generate_makefile_target,
    generate_shell_script,
)
```

### 2. Update Call Sites (if using parameter injection)

```python
# BEFORE
makefile = generate_makefile_target(config)

# AFTER
command = generate_command(config)
makefile = generate_makefile_target(config, command)
```

### 3. Update Test Files

Split imports between modules and update function calls with new parameters.

**Mock targets usually do not move.** Step 1 leaves `wizard.py` importing the
function back (`from ... import generate_makefile_target`), so a test that mocks
a call made *inside* `run_wizard` keeps `@patch("wizard.X")` — patching
`wizard_generators.X` replaces the definition, not the name the caller resolves,
and the mock silently never fires. See
[references/test-migration-patterns.md](references/test-migration-patterns.md)
Pattern 2 for the measured comparison.

### 4. Common Import Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `ImportError: circular import` | Runtime circular dependency | TYPE_CHECKING or parameter injection |
| `NameError: name 'X' is not defined` | Missing import after extraction | Add import from new module |
| `TypeError: missing positional argument` | Signature changed | Update call sites with new parameters |
| `F401: imported but unused` | Old import not cleaned up | `ruff check --fix` |

---

## Invocation

This is a Claude Code skill, not a command-line program. There is no argument
parser: the frontmatter declares `argument-hint: <refactoring-type>`, and
`$ARGUMENTS` (line 12) receives everything after the skill name as one string.

```text
/jmo-refactoring-assistant split_file scripts/cli/jmo.py
```

Name the target and the refactoring type in plain language. The vocabulary below
belongs in that sentence; it is not a flag set.

> **Removed, not reworded.** Earlier revisions documented `--target`,
> `--refactor-type`, `--function`, `--base-class-name`, `--max-lines`,
> `--output-dir`, `--dry-run`, `--skip-tests`, `--preserve-coverage` and
> `--avoid-circular-imports` as options. **None was ever implemented** — nothing
> in this repository parses any of them. They are deleted rather than corrected
> because a documented `--dry-run` reads as a guarantee that nothing is written,
> and a documented `--skip-tests` reads as permission to skip Phase 4.

### Refactoring Types

**`extract_monolith`** - Decompose large function into smaller components. Extracts embedded functions, creates orchestrator classes, generates ToolRunner/ScanOrchestrator pattern.

**`migrate_to_base_pattern`** - Apply inheritance pattern to similar classes. Creates abstract base class, eliminates duplication, enforces schema/API consistency.

**`split_file`** - Split oversized file into modules. For data: extract to `*_constants.py`, `*_frameworks.py`. For functions: extract to `*_helpers.py`, `*_orchestrators.py`. Avoids circular imports with TYPE_CHECKING.

**`extract_function`** - Extract 1-5 related functions to new module. Resolves circular imports with TYPE_CHECKING + parameter passing. Generates test stubs.

**`consolidate_duplicates`** - Merge duplicate code blocks. Detects similar patterns, creates shared utility functions.

### Scope and Safety

File access is whatever `allowed-tools` grants (`Read, Write, Edit, Glob, Grep,
Bash`), mediated by Claude Code's permission prompts. **Nothing canonicalizes a
path you name or rejects a `../` in it**, so the following are working rules for
whoever runs the skill, not settings that enforce themselves:

| Rule | Why it is not automatic |
|------|-------------------------|
| Refactor only inside this repository's working tree | A target resolving outside the tree is edited like any other; there is no containment check to fail |
| New files land beside their source unless you say otherwise | There is no output directory to configure — say where you want them |
| Always run Phase 4 (Test Migration) | It is the only regression guard this skill has; nothing detects that it was skipped |
| Commit or stash before starting | Edits apply directly. There is no preview mode, so `git diff` is the review step |
| Keep coverage at or above the pre-refactor number | Behaviour-preserving refactoring should not move it at all — a drop means tests were lost, not that a threshold was missed |

---

## Success Metrics

After using this skill, you should see:

- **Cyclomatic Complexity:** Max CC <=10 (from 252)
- **File Length:** Max file <=600 lines (from 2,456)
- **Code Duplication:** <50 duplicate lines (from 426)
- **Test Coverage:** >= before refactoring
- **All Tests Passing:** Green test suite
- **Zero Circular Imports:** TYPE_CHECKING pattern used
- **Clean Linting:** Ruff + black pass

**Real Results from Tasks 3.5 & 3.6:**

- compliance_mapper.py: 1,278 -> 399 lines (69% reduction)
- wizard.py: 959 -> 825 lines (14% reduction)
- Zero circular imports (TYPE_CHECKING + parameter injection)
- 150/152 tests passing (2 pre-existing failures)
- Coverage maintained (100% compliance, 97% wizard)

---

## Related Agent Findings

This skill addresses:

- **CRITICAL-001:** Extreme cyclomatic complexity in cmd_scan()
- **CRITICAL-002:** Code duplication across adapters
- **HIGH-001:** Embedded 777-line job() function
- **HIGH-002:** File length violations (Tasks 3.5, 3.6 completed)
- **MEDIUM-001:** Duplicate job functions for target types

**Total:** 5 CRITICAL/HIGH issues (2 completed, 3 remaining)

---

## Integration with Other Skills

**Use BEFORE:** `code-quality-auditor` (find targets), `dependency-analyzer` (map dependencies, detect circular imports)

**Use AFTER:** `jmo-test-fabricator` (generate missing tests), `jmo-documentation-updater` (update docs)

**Use WITH:** `coverage-gap-finder` (monitor coverage during refactoring)

---

## Reference Documents

- **[examples/real-world-examples.md](examples/real-world-examples.md)** - Complete before/after results from Task 3.5 (compliance_mapper split) and Task 3.6 (wizard generator extraction), including metrics, strategies, and lessons learned.

- **[references/test-migration-patterns.md](references/test-migration-patterns.md)** - Three test migration patterns (direct import split, mock update, integration test), plus a step-by-step test migration checklist.

- **[references/best-practices-troubleshooting.md](references/best-practices-troubleshooting.md)** - Pre/during/post refactoring checklists, seven common error scenarios with causes and fixes, and an import error reference table.

- **[references/limitations.md](references/limitations.md)** - What this skill does not do, six known edge cases (dynamic imports, monkeypatching, global state), and when to prefer manual refactoring.

- **[references/memory-integration.md](references/memory-integration.md)** - Memory namespace layout, cached pattern files, query examples, JSON storage format, cache management commands, and real-world workflow showing 30% time savings on repeated refactorings.
