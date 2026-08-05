# Memory Integration Pattern Guide

Shared reference for all JMo Security skills that use `.jmo/memory/` for cross-session persistence.

## Architecture

JMo Security skills use a file-based memory system stored in `.jmo/memory/` (gitignored). Each skill has its own namespace to avoid collisions.

### Namespace Conventions

| Skill | Namespace | Example File |
|-------|-----------|-------------|
| adapter-generator | `adapters/` | `.jmo/memory/adapters/trivy.json` |
| test-fabricator | `test-patterns/` | `.jmo/memory/test-patterns/trivy.json` |
| compliance-mapper | `compliance/` | `.jmo/memory/compliance/CWE-79.json` |
| profile-optimizer | `profiles/` | `.jmo/memory/profiles/balanced.json` |
| ci-debugger | `ci-fixes/` | `.jmo/memory/ci-fixes/sarif-upload.json` |
| security-hardening | `hardening/` | `.jmo/memory/hardening/CWE-78.json` |
| refactoring-assistant | `refactoring/` | `.jmo/memory/refactoring/monolith-split.json` |
| systematic-debugging | `debugging/` | `.jmo/memory/debugging/adapter-crash.json` |
| documentation-updater | `doc-updates/` | `.jmo/memory/doc-updates/last-sync.json` |
| target-type-expander | `target-types/` | `.jmo/memory/target-types/cloud-aws.json` |

## Query-Before-Work Pattern

Every memory-integrated skill follows this pattern:

```text
1. QUERY: Check if relevant memory exists for the current task
2. HIT:   Use cached patterns, skip redundant analysis (30-50% time savings)
3. MISS:  Perform full analysis, generate results
4. STORE: Save patterns for future reuse
```

### Implementation

```bash
# Step 1: Check for cached pattern
cat .jmo/memory/{namespace}/{key}.json 2>/dev/null

# Step 2: If hit, extract and reuse
cat .jmo/memory/{namespace}/{key}.json | jq '.patterns'

# Step 3: After completing work, store for next time
mkdir -p .jmo/memory/{namespace}
cat > .jmo/memory/{namespace}/{key}.json << 'EOF'
{
  "tool": "tool-name",
  "patterns": { ... },
  "metadata": {
    "last_updated": "2026-02-15",
    "usage_count": 1,
    "success_rate": 1.0
  }
}
EOF
```

## Storage Format (JSON)

All memory files follow a consistent JSON structure:

```json
{
  "tool": "identifier",
  "patterns": {
    "key_pattern_1": "...",
    "key_pattern_2": "..."
  },
  "metadata": {
    "last_updated": "ISO-date",
    "usage_count": 0,
    "success_rate": 0.0,
    "avg_time_saved_minutes": 0
  }
}
```

## Cross-Skill Memory Sharing

Skills can read each other's memory for richer context:

| Consumer Skill | Reads From | Purpose |
|---------------|------------|---------|
| test-fabricator | `adapters/` | Reuse adapter schema knowledge for test fixtures |
| ci-debugger | `ci-fixes/` | Check if failure pattern was seen before |
| compliance-mapper | `adapters/` | Know which tools map to which findings |
| documentation-updater | All namespaces | Detect what changed since last sync |

## Cache Management

```bash
# List all cached memories
find .jmo/memory -name "*.json" -type f

# Check memory size
du -sh .jmo/memory/

# Clear a specific namespace
rm -rf .jmo/memory/{namespace}/

# View usage statistics across all namespaces
find .jmo/memory -name "*.json" -exec jq -r '"\(.tool // "unknown"): used \(.metadata.usage_count // 0) times"' {} \;
```

## Time Savings

Memory integration typically provides 30-50% time savings on repeated tasks:

- **First run:** Full analysis, no cache benefit
- **Subsequent runs:** Skip redundant analysis, reuse patterns
- **Cross-tool:** Similar tools benefit from related cached patterns

## Important Notes

- `.jmo/memory/` is **gitignored** — private to local development
- Memory files are plain JSON — human-readable and editable
- Skills should gracefully handle missing memory (cache miss = normal operation)
- Memory is not shared between team members (each developer has their own)
