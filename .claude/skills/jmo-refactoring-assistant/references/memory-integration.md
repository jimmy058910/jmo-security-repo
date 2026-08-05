# Memory Integration

**Memory Namespace:** `.jmo/memory/refactoring/`

---

## What's Stored

- **Refactoring Patterns:** Extract Method, Introduce Parameter Object, Replace Conditional with Polymorphism, BaseAdapter migration
- **Architectural Decisions:** When to use dependency injection, factory patterns, circular dependency resolution strategies
- **Safety Checks:** Test coverage thresholds (85%), rollback procedures, pre/post-refactor validations
- **Code Smell Signatures:** Cyclomatic complexity scores, function length thresholds, coupling metrics
- **Success Metrics:** Coverage maintained, tests passing, import cleanup effectiveness

---

## Query Before Analysis

```bash
# Check if "Extract Method" pattern cached
cat .jmo/memory/refactoring/extract-method.json | jq '.steps'
# Returns: ["Identify code smell", "Create new method", "Move code", "Update tests", "Verify coverage maintained"]

# Check if BaseAdapter migration pattern cached
cat .jmo/memory/refactoring/base-adapter-migration.json | jq '.checklist'
# Returns: ["Inherit BaseAdapter", "Remove duplicate code", "Update tests", "Verify all adapters work"]

# Check if circular dependency fix pattern cached
cat .jmo/memory/refactoring/circular-imports.json | jq '.solutions'
# Returns: ["TYPE_CHECKING pattern", "Move shared code to utils", "Restructure modules"]
```

---

## Storage Format (JSON)

```json
{
  "refactoring_type": "extract-method",
  "pattern": {
    "name": "Extract Method",
    "category": "Composing Methods",
    "when_to_use": "Function >50 lines OR cyclomatic complexity >10",
    "steps": [
      "Identify code smell (long method, duplicate code)",
      "Determine extraction boundary (preserve behavior)",
      "Create new method with descriptive name",
      "Move code to new method",
      "Replace original code with method call",
      "Update tests (may need new test for extracted method)",
      "Verify coverage maintained (>=85%)"
    ]
  },
  "jmo_specific_examples": [
    {
      "file": "scripts/cli/jmo.py",
      "function": "cmd_scan",
      "smell": "function too long (450 lines)",
      "extracted_methods": [
        "_iter_repos",
        "_iter_images",
        "_iter_iac",
        "_iter_urls",
        "_iter_gitlab",
        "_iter_k8s"
      ],
      "outcome": "Reduced from 450 lines to 6 iterator functions + 150 line orchestrator"
    }
  ],
  "safety_checks": {
    "pre_refactor": [
      "git status (ensure clean working tree)",
      "pytest --cov=scripts (baseline coverage)",
      "git checkout -b refactor/extract-method"
    ],
    "post_refactor": [
      "pytest --cov=scripts --cov-fail-under=85",
      "make lint (ensure no new violations)",
      "git diff (review all changes)"
    ],
    "rollback": "git checkout main && git branch -D refactor/extract-method"
  },
  "metadata": {
    "last_updated": "2025-10-24",
    "usage_count": 8,
    "success_rate": 0.95,
    "avg_time_saved_hours": 2.5
  }
}
```

---

## Time Savings

30% faster repeated refactorings (8-12 hours -> 5.5-8.5 hours)

### Example Workflow

1. **Query Memory:** Claude checks `.jmo/memory/refactoring/extract-method.json` before refactoring
2. **Cache Hit:** If cached, retrieve refactoring pattern instantly (<1 second)
   - Skip pattern research (saves 30 min)
   - Skip checklist creation (saves 15 min)
   - Use proven safety checks (saves 20 min)
   - **Total Savings:** 1-1.5 hours
3. **Cache Miss:** If not cached, determine refactoring approach (1.5 hours)
   - Research Extract Method pattern
   - Create JMo-specific checklist
   - Define safety checks
4. **Execute Refactoring:** Use cached or new pattern (5-8 hours)
5. **Store Result:** Save pattern and outcome in memory for reuse

---

## Memory Invalidation

- **Manual:** Delete `.jmo/memory/refactoring/extract-method.json` to force fresh analysis
- **Automatic:** Cache valid indefinitely (refactoring patterns rarely change)
- **Architecture Change:** Invalidate when core architecture changes (e.g., BaseAdapter pattern introduced)

---

## Cached Pattern Files

```bash
.jmo/memory/refactoring/extract-method.json
.jmo/memory/refactoring/parameter-object.json
.jmo/memory/refactoring/replace-conditional.json
.jmo/memory/refactoring/base-adapter-migration.json    # JMo-specific
.jmo/memory/refactoring/circular-imports.json
.jmo/memory/refactoring/dependency-injection.json
.jmo/memory/refactoring/factory-pattern.json
```

---

## Real-World Workflow Examples

### First Time (No Cache) - wizard.py

```text
User: "Refactor wizard.py - too many responsibilities"

Claude:
1. Analyzes wizard.py (45 min)
   - Identifies 5 responsibilities
2. Researches Extract Class pattern (30 min)
3. Creates refactoring plan (30 min)
4. Executes refactoring (6 hours)
5. STORES in .jmo/memory/refactoring/extract-class.json

Total: 8-9 hours
```

### Second Time (With Cache) - jmo.py

```text
User: "Refactor jmo.py - cmd_scan function too complex"

Claude:
1. QUERIES .jmo/memory/refactoring/extract-class.json (instant)
   - Retrieves pattern, checklist, safety checks
2. Analyzes cmd_scan (30 min)
3. Executes refactoring (5 hours)
   - Uses cached pattern (SKIP research)
   - Follows cached checklist (SKIP planning)

Total: 5.5-6 hours (30% savings)
```

---

## Dependency-Analyzer Integration

Before major refactorings, use memory to store dependency analysis results:

```bash
# Store dependency analysis for cmd_scan
cat > .jmo/memory/refactoring/cmd_scan-dependencies.json <<'EOF'
{
  "file": "scripts/cli/jmo.py",
  "function": "cmd_scan",
  "imported_by": ["scripts/cli/jmotools.py", "tests/integration/test_cli_scan_ci.py"],
  "imports": ["scripts.core.config", "scripts.core.normalize_and_report"],
  "refactoring_constraints": [
    "47 files import cmd_scan - preserve function signature",
    "No circular dependencies detected - safe to extract",
    "Safe to extract helper functions - no external coupling"
  ]
}
EOF
```

---

## Architectural Decision Records (ADRs)

Cache architectural decisions to ensure consistency:

```json
{
  "decision": "when-to-use-base-adapter",
  "context": "All tool adapters have common patterns (load JSON, normalize, fingerprint)",
  "chosen": "BaseAdapter with inheritance",
  "rationale": "Reduces duplication, enforces consistency, easier to add compliance enrichment",
  "when_to_apply": "When adding new tool adapter OR 3+ adapters share >50% code",
  "when_NOT_to_apply": "Tool has unique output format incompatible with base pattern"
}
```

---

## Coverage Preservation Strategy

Memory stores proven coverage preservation techniques:

```json
{
  "strategy": "maintain-85-percent-coverage",
  "techniques": [
    {"name": "Baseline First", "command": "pytest --cov=scripts --cov-report=term-missing > baseline.txt"},
    {"name": "Incremental Testing", "command": "pytest --cov=scripts.cli.jmo --cov-fail-under=85"},
    {"name": "New Function Coverage", "command": "pytest --cov=scripts.cli.jmo::cmd_scan --cov-fail-under=90"}
  ],
  "rollback_if": [
    "Coverage drops below 85%",
    "New functions have <80% coverage",
    "Integration tests fail"
  ]
}
```

---

## Cache Management

```bash
# Review all cached refactoring patterns
ls -lh .jmo/memory/refactoring/

# View success rates across patterns
cat .jmo/memory/refactoring/*.json | jq -r '.pattern.name + ": " + (.metadata.success_rate | tostring)'

# Find most-used patterns
cat .jmo/memory/refactoring/*.json | jq -r '.pattern.name + ": " + (.metadata.usage_count | tostring)' | sort -t: -k2 -rn

# Invalidate outdated architectural decision
rm .jmo/memory/refactoring/base-adapter-migration.json
```
