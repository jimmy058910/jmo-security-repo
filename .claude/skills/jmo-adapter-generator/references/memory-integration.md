# Memory Integration Patterns

Memory integration accelerates adapter generation by caching tool patterns, test fixtures, and common pitfalls.

---

## Phase 0: Memory Query

**Purpose:** Check if tool patterns already known before starting research.

**Actions:**

```bash
# Check memory for existing patterns
cat .jmo/memory/adapters/{tool}.json 2>/dev/null | jq .

# If found: Reuse patterns (saves 30-45 min)
# If not found: Run full research
```

**Time Savings:**
- Memory hit: Skip 30-45 min research
- Memory miss: No penalty, continue as normal

**Memory Integration in Phase 1:**
- Compare discovered format with memory (if exists)
- Note discrepancies (tool version changes?)

---

## Phase 8: Store Memory

**Purpose:** Persist learned patterns for future adapters.

**Action:**

```python
from scripts.core.memory import store_memory

memory_data = {
    "tool": "{tool}",
    "version": "{detected_version}",
    "output_format": "results[].vulnerabilities[]",
    "exit_codes": {
        "0": "clean",
        "1": "findings",
        "2": "error"
    },
    "common_pitfalls": [
        "Requires {TOOL}_TOKEN environment variable",
        "Large repos timeout (increase to 1200s)",
        "JSON output malformed if --json flag missing"
    ],
    "test_fixtures": [
        {
            "name": "vuln_high_severity",
            "path": f"tests/adapters/fixtures/{tool}_high.json",
            "scenario": "2 HIGH vulnerabilities in dependencies"
        }
    ],
    "plugin_metadata": {
        "name": "{tool}",
        "schema_version": "1.2.0",
        "exit_codes": {"0": "clean", "1": "findings", "2": "error"}
    },
    "last_updated": "2025-10-31",
    "created_by": "jmo-adapter-generator v3.0.0"
}

store_memory("adapters", "{tool}", memory_data)
print(f"[memory] Stored {tool} patterns in .jmo/memory/adapters/{tool}.json")
```

**Memory File Location:** `.jmo/memory/adapters/{tool}.json`

---

## Memory-Enhanced Features

- **Plugin Metadata Caching:** Store exit codes, output formats in memory
- **Test Fixture Library:** Reuse fixtures across similar tools
- **Compliance Auto-Enrichment:** Pre-populate compliance fields
- **Time Savings:** 42% faster than v2.1.0 (4.3h to 2.5h)

---

## Time Savings Comparison

### v3.0.0 (Plugin Architecture)

| Phase | Duration | Memory Hit | Notes |
|-------|----------|------------|-------|
| Memory query (Phase 0) | 2 min | - | Check cache |
| Research (Phase 1) | 15 min | 5 min | Reuse patterns |
| Create adapter (Phase 2) | 30 min | 20 min | Plugin template |
| Write tests (Phase 3) | 45 min | 30 min | Fixtures from memory |
| CLI integration (Phase 4) | 0 min | 0 min | AUTO-DISCOVERY |
| Config (Phase 5) | 10 min | 10 min | - |
| Docs (Phase 6) | 30 min | 30 min | - |
| Docker/Wizard (Phase 6.5) | 20 min | 20 min | - |
| Integration tests (Phase 7) | 20 min | 20 min | - |
| Store memory (Phase 8) | 5 min | 5 min | - |
| Validation (Phase 9) | 15 min | 15 min | - |
| PR creation (Phase 10) | 5 min | 5 min | - |
| **Total** | **197 min (3.3h)** | **160 min (2.7h)** | **42% savings** |

**Comparison to v2.1.0 (Non-Memory, Non-Plugin):**
- v2.1.0: 260 min (4.3 hours)
- v3.0.0 (memory hit): 160 min (2.7 hours)
- Improvement: 100 min (38% faster)
