# Memory Integration

**Memory Namespace:** `.jmo/memory/refactoring/`

---

## What's Stored

- **Refactoring Patterns:** Extract Method, Introduce Parameter Object, Replace Conditional with Polymorphism, extract-to-shared-helper
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

# Check if the shared-helper extraction pattern is cached
cat .jmo/memory/refactoring/extract-shared-helper.json | jq '.checklist'
# Returns: ["Add helper to adapters/common.py", "Route adapters through it", "Update tests", "Verify all adapters work"]

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
      "git rev-parse --abbrev-ref HEAD (record the base branch; do not assume main)",
      "pytest --cov=scripts (record the baseline percentage)",
      "git switch -c refactor/extract-method"
    ],
    "post_refactor": [
      "pytest --cov=scripts (compare against the recorded baseline)",
      "make lint (ensure no new violations)",
      "git diff (review all changes)"
    ],
    "rollback": [
      "git stash -u (preserve uncommitted work; never discard it to switch away)",
      "git switch - (return to the recorded base branch)",
      "KEEP refactor/extract-method until its commits are confirmed reachable elsewhere",
      "git branch -d refactor/extract-method (only after that; -d refuses unmerged work, which is the point)"
    ]
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
- **Architecture Change:** Invalidate when core architecture changes (e.g., a new adapter contract replacing `@adapter_plugin`)

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
  "decision": "how-tool-adapters-share-code",
  "context": "All tool adapters have common patterns (load JSON, normalize, fingerprint)",
  "chosen": "Composition: @adapter_plugin + AdapterPlugin.parse(), with shared helpers in adapters/common.py",
  "rationale": "The plugin loader registers AdapterPlugin subclasses only; shared behaviour lives in common.py (safe_load_json_file / safe_load_ndjson_file) and common_finding.fingerprint",
  "when_to_apply": "Every new tool adapter -- see .claude/rules/adapters.rules.md",
  "when_NOT_to_apply": "n/a; there is no second adapter contract",
  "superseded": "An earlier record here chose 'BaseAdapter with inheritance'. That class was subclassed by nothing, implemented a different contract (dicts, its own fingerprinting), and has been deleted."
}
```

---

## Coverage Preservation Strategy

Memory stores proven coverage preservation techniques:

```json
{
  "strategy": "hold-coverage-at-the-recorded-baseline",
  "techniques": [
    {"name": "Baseline First", "command": "pytest --cov=scripts --cov-report=term-missing > baseline.txt"},
    {"name": "Incremental Testing", "command": "pytest --cov=scripts --cov-report=term-missing tests/cli/"},
    {"name": "New Function Coverage", "command": "pytest --cov=scripts.cli.wizard_generators --cov-report=term-missing tests/unit/test_wizard_generators.py"}
  ],
  "rollback_if": [
    "Total coverage is below the baseline recorded in baseline.txt",
    "A file touched by the refactor lost coverage even though total held",
    "Integration tests fail"
  ]
}
```

**Compare against the baseline, not against a fixed percentage.** Earlier
revisions of this file passed `--cov-fail-under=85` and `--cov-fail-under=90` and
named the strategy `maintain-85-percent-coverage`. **No such floor exists in this
repository**: `Makefile:132` runs `pytest --cov --cov-report=term-missing` with
no threshold, `[tool.coverage.report]` in `pyproject.toml` sets no `fail_under`,
and CI's only enforced gate is `coverage_pct < 80` at
[`coverage-aggregate`'s "Verify coverage threshold" step](../../../../.github/workflows/ci.yml). A refactor
that quietly drops coverage from 87% to 86% passes every one of those, which is
exactly why the recorded baseline — not a constant — is the thing to diff against.
Tracked as issue #756.

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
