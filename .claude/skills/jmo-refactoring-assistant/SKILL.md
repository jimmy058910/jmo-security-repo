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

Systematically decompose monolithic functions, migrate to design patterns (BaseAdapter), and split oversized files while preserving test coverage and preventing regressions.

This skill helps you refactor the JMo Security codebase by:

1. **Decomposing monolithic functions** (e.g., cmd_scan: 1,553 lines, CC 252)
2. **Migrating to design patterns** (e.g., BaseAdapter for 14 tool adapters)
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
| CRITICAL-002 | BaseAdapter pattern migration (14 adapters) | Remaining |
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
| 14 adapters with duplicate code | `migrate_to_base_pattern` | BaseAdapter (future) |
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

Split imports between modules, update function calls with new parameters, update mock paths (`@patch("wizard.X")` -> `@patch("wizard_generators.X")`).

### 4. Common Import Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `ImportError: circular import` | Runtime circular dependency | TYPE_CHECKING or parameter injection |
| `NameError: name 'X' is not defined` | Missing import after extraction | Add import from new module |
| `TypeError: missing positional argument` | Signature changed | Update call sites with new parameters |
| `F401: imported but unused` | Old import not cleaned up | `ruff check --fix` |

---

## Parameters

### Required

- `--target PATH`: File or directory to refactor
- `--refactor-type TYPE`: One of the types below

### Refactoring Types

**`extract_monolith`** - Decompose large function into smaller components. Extracts embedded functions, creates orchestrator classes, generates ToolRunner/ScanOrchestrator pattern.

**`migrate_to_base_pattern`** - Apply inheritance pattern to similar classes. Creates abstract base class, eliminates duplication, enforces schema/API consistency.

**`split_file`** - Split oversized file into modules. For data: extract to `*_constants.py`, `*_frameworks.py`. For functions: extract to `*_helpers.py`, `*_orchestrators.py`. Avoids circular imports with TYPE_CHECKING.

**`extract_function`** - Extract 1-5 related functions to new module. Resolves circular imports with TYPE_CHECKING + parameter passing. Generates test stubs.

**`consolidate_duplicates`** - Merge duplicate code blocks. Detects similar patterns, creates shared utility functions.

### Optional

- `--function NAME`: Specific function to refactor (for extract_monolith)
- `--base-class-name NAME`: Name for generated base class (for migrate_to_base_pattern)
- `--max-lines N`: Maximum lines per file (for split_file, default: 500)
- `--output-dir PATH`: Where to create new files (default: same directory)
- `--dry-run`: Preview changes without applying
- `--skip-tests`: Skip test migration (not recommended)
- `--preserve-coverage`: Fail if coverage decreases (default: true)
- `--avoid-circular-imports`: Use TYPE_CHECKING pattern (default: true)

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
