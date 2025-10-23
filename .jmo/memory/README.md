# Memory System User Guide

## Overview

The `.jmo/memory/` system is JMo Security's persistent learning layer - a hybrid automated/manual system that caches analysis patterns to reduce repeated work.

**Think of it like:** Git's `.git/` directory - mostly automated, but you can peek inside when needed.

---

## How It Works

### Automated (80% of Usage)

Claude Code automatically:

- ✅ **Queries memory before re-analyzing** ("Have I seen this pattern before?")
- ✅ **Stores findings after skill completion** (tool patterns, compliance mappings, etc.)
- ✅ **Updates namespace-scoped data** (adapters, profiles, compliance)
- ✅ **Retrieves cached results** for common queries

**You don't need to do anything** - it just speeds up repeated tasks.

### Manual (20% of Usage)

You manually interact when:

- 📝 **Reviewing memory contents:** `cat .jmo/memory/adapters/snyk.json`
- 🗑️ **Pruning outdated entries:** `rm .jmo/memory/adapters/deprecated-tool.json`
- 🔧 **Overriding cached data:** Edit JSON if Claude's analysis was wrong
- 📊 **Analyzing trends:** `jq '.success_rate' .jmo/memory/*/*.json`

---

## Concrete User Workflows

### Scenario 1: Adding New Adapter (Automated)

```bash
# You: "Add support for Snyk scanner"

# Claude automatically:
# 1. Checks: .jmo/memory/adapters/snyk.json (not found)
# 2. Uses jmo-adapter-generator skill (full 7-step workflow)
# 3. Stores result:
cat .jmo/memory/adapters/snyk.json
{
  "tool": "snyk",
  "output_format": "results[].vulnerabilities[]",
  "exit_codes": {"0": "clean", "1": "findings", "2": "error"},
  "common_pitfalls": ["Requires SNYK_TOKEN", "Large repos timeout"],
  "last_updated": "2025-10-21"
}

# Next time: "Update Snyk adapter for v2.0 API changes"
# Claude retrieves .jmo/memory/adapters/snyk.json
# - Already knows exit codes (skip research)
# - Already has test patterns (faster updates)
# - 40% time savings ✅
```

### Scenario 2: Compliance Mapping (Automated)

```bash
# You: "Map CWE-79 to compliance frameworks"

# Claude automatically:
# 1. Checks: .jmo/memory/compliance/cwe-79.json
# 2. If exists: "I already mapped this to OWASP A03:2021, CWE Top 25 rank #2, etc."
# 3. If not exists: Research → map → store result

# Manual review (optional):
cat .jmo/memory/compliance/cwe-79.json
{
  "cwe": "CWE-79",
  "frameworks": {
    "owasp": ["A03:2021"],
    "cwe_top_25": {"rank": 2, "category": "Injection"},
    "pci_dss": ["6.5.7", "11.3.2"]
  },
  "last_updated": "2025-10-21"
}
```

### Scenario 3: Profile Optimization (Manual Review)

```bash
# You: "Optimize balanced profile for faster scans"

# Claude automatically:
# 1. Generates timings.json analysis
# 2. Stores: .jmo/memory/profiles/balanced-optimization.json
# 3. Recommends changes

# You manually review the recommendations:
cat .jmo/memory/profiles/balanced-optimization.json
{
  "bottlenecks": ["trivy: 180s", "zap: 120s"],
  "recommendations": [
    "Increase threads: 4 → 6 (25% speedup)",
    "Add trivy flags: --scanners vuln,secret (skip misconfig)"
  ],
  "expected_speedup": "35%"
}

# You decide: "Apply recommendation 1, skip recommendation 2"
# Claude updates jmo.yml based on your choice
```

### Scenario 4: Pruning Outdated Memory (Manual)

```bash
# After 6 months, you clean up:
ls -lh .jmo/memory/adapters/
# -rw-r--r-- snyk.json (last modified: 2 months ago) ← Keep
# -rw-r--r-- gitleaks.json (last modified: 10 months ago) ← DELETE (deprecated)

rm .jmo/memory/adapters/gitleaks.json

# Future: Memory CLI
jmotools memory prune --older-than 180d
```

---

## When to Manually Interact

| Situation | Action | Frequency |
|-----------|--------|-----------|
| **Verify cached data is accurate** | `cat .jmo/memory/<namespace>/<item>.json` | Occasionally (after major version changes) |
| **Override incorrect analysis** | Edit JSON file directly | Rarely (if Claude makes a mistake) |
| **Clean up old entries** | `rm .jmo/memory/<namespace>/<item>.json` | Quarterly cleanup |
| **Analyze trends** | `jq '.success_rate' .jmo/memory/*/*.json` | Monthly (for metrics) |
| **Backup memory** | `tar -czf memory-backup.tar.gz .jmo/memory/` | Before major refactors |

---

## Memory Privacy & Security

### What's Stored

✅ **Safe to Store:**

- Tool output patterns (e.g., "Snyk uses `vulnerabilities[]` array")
- Common pitfalls (e.g., "Trivy exits with code 1 on findings, treat as success")
- Performance metrics (e.g., "Semgrep averages 45s on 10k LOC repos")
- Compliance mappings (e.g., "CWE-79 → OWASP A03:2021")

❌ **NOT Stored:**

- Actual security findings (those go in `results/`)
- Secrets or credentials
- Repository names or code snippets
- Personal data

### Privacy Guarantees

- `.jmo/memory/` is **gitignored** (never committed to your repo)
- **Local storage only** (not synced to cloud)
- **No API calls** (all processing local)
- **Safe to delete** (regenerates on next use)

---

## Expected Time Savings

| Skill | Memory Namespace | Query Pattern | Time Savings |
|-------|-----------------|---------------|--------------|
| jmo-adapter-generator | adapters/ | "Have I added this tool?" | 40% on repeated tasks |
| jmo-compliance-mapper | compliance/ | "What frameworks map?" | 60% on repeated mappings |
| jmo-profile-optimizer | profiles/ | "What optimizations worked?" | 50% on repeated profiles |
| jmo-refactoring-assistant | refactoring/ | "What refactorings done?" | 30% on similar refactors |
| jmo-security-hardening | security/ | "How did I fix this CWE?" | 45% on similar vulns |

**Overall:** 30-40% reduction in repeated analysis time.

---

## Troubleshooting

### Memory file not being created

**Symptom:** Skill completes but no `.jmo/memory/<namespace>/<item>.json` created

**Causes:**

1. Directory doesn't exist: `mkdir -p .jmo/memory/<namespace>`
2. Permission denied: `chmod 755 .jmo/memory`
3. Skill doesn't have memory integration yet (see Files 16-18 for updated skills)

**Fix:**

```bash
mkdir -p .jmo/memory/{adapters,compliance,profiles,target-types,refactoring,security}
```

### Memory query returns stale data

**Symptom:** Claude uses outdated pattern from memory

**Causes:**

1. Tool version changed but memory not updated
2. JMo codebase patterns changed

**Fix:**

```bash
# Delete stale entry
rm .jmo/memory/adapters/tool.json

# Claude will re-analyze on next use
```

### Memory directory too large (>100 MB)

**Symptom:** `.jmo/memory/` consuming excessive disk space

**Causes:**

1. Too many old patterns accumulated
2. JSON files contain large data (e.g., full tool outputs instead of patterns)

**Fix:**

```bash
# Prune old files (>6 months)
find .jmo/memory -name "*.json" -mtime +180 -delete

# Archive instead of delete
mkdir .jmo/memory/archive
find .jmo/memory -name "*.json" -mtime +180 -exec mv {} .jmo/memory/archive/ \;
```

---

## FAQ

### Q: Is memory shared across projects?

**A:** No. Each project has its own `.jmo/memory/` directory. If you work on multiple JMo forks, each has separate memory.

### Q: Can I commit memory files to Git?

**A:** **No.** Memory files are gitignored and should never be committed (they contain project-specific patterns, not shareable across contributors).

### Q: What if I accidentally delete all memory?

**A:** No problem. Claude will regenerate memory as you use skills. You'll lose time-savings benefits temporarily, but no data loss (findings are in `results/`, not memory).

### Q: Can I pre-populate memory with patterns?

**A:** Yes. Create JSON files manually in `.jmo/memory/<namespace>/` following the schemas in File 5 (05-memory-structure.md).

### Q: How do I backup memory before a major change?

**A:**
```bash
tar -czf memory-backup-$(date +%Y%m%d).tar.gz .jmo/memory/
# Restore: tar -xzf memory-backup-YYYYMMDD.tar.gz
```

---

**Last Updated:** 2025-10-21
**Document Version:** 1.0.0
**Maintained By:** JMo Security Contributors
