# Memory Integration Reference

Memory namespace patterns and caching strategies for CI fix patterns.

---

## Memory Namespace

**Namespace:** `.jmo/memory/ci-fixes/`

**What's Stored:**

- **Common CI failure patterns:** Docker tag extraction, actionlint errors, SARIF upload permissions
- **Proven fixes from CLAUDE.md:** All 17 documented failure modes and solutions
- **Fix success rates:** Track which fixes work most reliably
- **GitHub Actions API changes:** Weekly updates to workflow syntax, action versions

---

## Query Before Fixing

```bash
# Check if CI failure pattern already known
cat .jmo/memory/ci-fixes/docker-tag-extraction.json | jq '.solution'
# Returns: "Extract tag from metadata-action output, not github.ref_name"

# Check actionlint fix
cat .jmo/memory/ci-fixes/actionlint-fail-level.json | jq '.fix'
# Returns: "Replace fail_on_error with fail_level: error"

# Check frequency of failures
cat .jmo/memory/ci-fixes/sarif-upload-permissions.json | jq '.frequency'
# Returns: 8 (encountered 8 times)

# Check Ruff-after-Black pattern
cat .jmo/memory/ci-fixes/ruff-after-black.json | jq '.solution'
# Returns: "Run ruff check --fix after Black, review auto-fixes, commit both"
```

---

## Storage Format (JSON)

```json
{
  "pattern": "docker-tag-extraction",
  "error_message": "invalid reference format: v*",
  "section": "#1 Docker Tag Extraction Issues",
  "root_cause": "github.ref_name includes 'v' prefix, causes invalid tag",
  "solution": "Extract tag from metadata-action output using head/cut",
  "code_fix": "TEST_TAG=$(echo \"${{ steps.meta.outputs.tags }}\" | head -n1 | cut -d':' -f2)",
  "frequency": 3,
  "success_rate": 1.0,
  "last_encountered": "2025-10-15",
  "related_patterns": ["docker-testing-commands", "docker-hub-sync"],
  "time_to_fix": "2 min",
  "difficulty": "easy"
}
```

### Additional Pattern Examples

**Ruff After Black:**

```json
{
  "pattern": "ruff-after-black-cascade",
  "error_message": "F401 imported but unused / F541 f-string without placeholders",
  "section": "#15 Ruff Linting Failures After Black Formatting",
  "root_cause": "Black formats code, Ruff enforces quality (unused imports, f-strings)",
  "solution": "Run ruff check --fix after Black, review auto-removals, commit",
  "code_fix": "ruff check scripts/ tests/ --fix && git add . && git commit",
  "frequency": 1,
  "success_rate": 1.0,
  "last_encountered": "2025-11-01",
  "related_patterns": ["pre-commit-order", "nightly-lint-failures"],
  "time_to_fix": "5-10 min",
  "difficulty": "easy",
  "prevention": "pre-commit config: black -> ruff --fix -> ruff --no-fix"
}
```

**Platform Float Precision:**

```json
{
  "pattern": "platform-float-precision",
  "error_message": "assert 0.X <= Y (platform-specific float value)",
  "section": "#16 Platform-Specific Test Threshold Failures",
  "root_cause": "Floating-point precision differences across CPU architectures, compilers, Python versions",
  "solution": "Find min/max across ALL platforms, add 5-20% buffer, document in test",
  "code_fix": "assert MIN_VALUE * 0.95 <= value <= MAX_VALUE * 1.05  # Platform-safe range",
  "frequency": 1,
  "success_rate": 1.0,
  "last_encountered": "2025-11-06",
  "related_patterns": ["test-coverage", "nightly-lint-failures"],
  "time_to_fix": "20-30 min",
  "difficulty": "medium",
  "prevention": "Use pytest.approx(), test ranges not exact values, document expected ranges"
}
```

---

## Update After Fixing

```bash
# Increment frequency after next occurrence
jq '.frequency += 1 | .last_encountered = "2025-11-15"' \
  .jmo/memory/ci-fixes/ruff-after-black.json > tmp.json && mv tmp.json .jmo/memory/ci-fixes/ruff-after-black.json
```

---

## Time Savings

**50% faster repeated CI debugging (30-60m -> 15-30m)**

**Example Workflow:**

1. **CI fails:** "Resource not accessible by integration (SARIF upload)"
2. **Query memory:** Check `.jmo/memory/ci-fixes/sarif-upload-*.json`
3. **Memory hit:** Found pattern "sarif-upload-permissions"
4. **Apply fix:** Add `security-events: write` to workflow permissions
5. **Verify:** Push change, CI passes
6. **Update memory:** Increment frequency counter (now seen 9 times)
7. **Time saved:** 25 minutes (skipped diagnosis, went straight to fix)

**When memory misses:**

1. **No pattern found:** Use systematic debugging (jmo-systematic-debugging skill)
2. **Diagnose root cause:** Check workflow logs, GitHub Actions docs
3. **Implement fix:** Test locally if possible, then push
4. **Store in memory:** Save pattern for future use
5. **Update this skill:** Add new section to failure catalog
6. **Next time:** Pattern available for instant fix

---

## Memory Maintenance

- **Weekly:** Check for new GitHub Actions API changes (action versions, syntax)
- **Monthly:** Review high-frequency failures (>10 occurrences) for systemic issues
- **Quarterly:** Prune solved patterns (success_rate 1.0, frequency >20, not seen in 90 days)
- **Annually:** Archive deprecated patterns (old action versions, obsolete workflows)

---

## Cross-References

All fixes in this skill come from [CLAUDE.md](../../../CLAUDE.md). Memory integration ensures these lessons are:

1. **Instantly accessible:** Query memory instead of searching CLAUDE.md
2. **Tracked for frequency:** Know which issues are most common
3. **Validated for success:** Track which fixes work reliably
4. **Evolving:** New patterns added as CI/CD changes

**Related Memory Namespaces:**

- `.jmo/memory/debugging/` - General debugging patterns (jmo-systematic-debugging skill)
- `.jmo/memory/adapters/` - Tool adapter patterns (jmo-adapter-generator skill)
- `.jmo/memory/profiles/` - Performance optimization patterns (jmo-profile-optimizer skill)
