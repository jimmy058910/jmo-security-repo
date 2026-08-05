# Memory Integration

Caching failure patterns, root causes, and solutions for faster repeated debugging.

---

## Memory Namespace

`.jmo/memory/debugging/`

## What's Stored

- **Common failure modes:** Tool timeouts, exit code misinterpretations, schema validation errors
- **Root cause patterns:** Missing dependencies, version mismatches, configuration errors
- **Hypothesis testing history:** Success rates of different debugging approaches
- **JMo-specific patterns:** Two-phase architecture failures, multi-target issues, adapter parsing errors

## Query Before Debugging

```bash
# Check if failure pattern already known
cat .jmo/memory/debugging/tool-timeout-pattern.json | jq '.root_cause'
# Returns: "Tool timeout caused by large repository size, increase timeout to 1200s"

# Check exit code patterns
cat .jmo/memory/debugging/semgrep-exit-codes.json | jq '.exit_codes'
# Returns: {"0": "clean", "1": "findings", "2": "error"}
```

## Storage Format (JSON)

```json
{
  "pattern": "tool-timeout",
  "tool": "semgrep",
  "symptom": "Subprocess timeout after 600s",
  "root_cause": "Large repository with 50k+ LOC",
  "solution": "Increase timeout to 1200s in jmo.yml per_tool section",
  "frequency": 5,
  "success_rate": 1.0,
  "last_encountered": "2025-10-20",
  "related_patterns": ["trivy-timeout", "bandit-timeout"]
}
```

## Time Savings

35% faster repeated debugging (30-90m reduced to 20-60m).

## Example Workflow

1. **Encounter bug:** "Semgrep returns no findings on large repo"
2. **Query memory:** Check `.jmo/memory/debugging/semgrep-*.json`
3. **Memory hit:** Found pattern "semgrep-timeout-large-repo"
4. **Apply fix:** Increase timeout from 600s to 1200s
5. **Verify:** Run scan again, findings now appear
6. **Update memory:** Increment frequency counter
7. **Time saved:** 30 minutes (skipped root cause investigation)

## When Memory Misses

1. **No pattern found:** Continue with Phase 1 (Root Cause Investigation)
2. **Complete all 4 phases:** Find root cause, test hypothesis, implement fix
3. **Store in memory:** Save pattern for future use
4. **Next time:** Pattern available for instant fix

## Memory Maintenance

- **Weekly:** Review high-frequency patterns (>5 occurrences)
- **Monthly:** Prune stale patterns (>90 days, success_rate < 0.5)
- **Quarterly:** Consolidate similar patterns (semgrep-timeout-* to semgrep-timeout-general)

## Related Memory Namespaces

- `.jmo/memory/ci-fixes/` - CI-specific debugging patterns (jmo-ci-debugger skill)
- `.jmo/memory/adapters/` - Tool adapter patterns (jmo-adapter-generator skill)
- `.jmo/memory/profiles/` - Performance optimization patterns (jmo-profile-optimizer skill)
