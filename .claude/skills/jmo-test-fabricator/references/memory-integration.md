# Memory Integration

**Memory Namespace:** `.jmo/memory/test-patterns/`

## What's Stored

- **Test Templates:** Fabricated JSON fixtures by adapter type (trivy, semgrep, trufflehog, etc.)
- **Coverage Strategies:** Equivalence partitioning, boundary value analysis, edge case patterns
- **Exit Code Patterns:** Tool-specific expected exit codes (0=clean, 1=findings, 2=error)
- **Fabrication Patterns:** How to generate realistic test data for each tool's JSON schema
- **Common Pitfalls:** Known issues when testing specific adapters (NDJSON vs JSON array, etc.)

## Query Before Analysis

```bash
# Check if trivy test pattern cached
cat .jmo/memory/test-patterns/trivy.json | jq '.fabricated_json'
# Returns: {"Results": [{"Type": "vulnerabilities", "Vulnerabilities": [...]}]}

# Check if semgrep coverage strategy cached
cat .jmo/memory/test-patterns/semgrep.json | jq '.coverage_approach'
# Returns: "Equivalence partitioning: no findings, single finding, multiple findings per file"

# Check if trufflehog exit code pattern cached
cat .jmo/memory/test-patterns/trufflehog.json | jq '.exit_codes'
# Returns: {"0": "no secrets", "1": "secrets found", "183": "verified secrets"}
```

## Storage Format (JSON)

```json
{
  "tool": "trivy",
  "adapter_file": "scripts/core/adapters/trivy_adapter.py",
  "json_schema": {
    "root": "Results[]",
    "vulnerability": {
      "VulnerabilityID": "CVE-2024-1234",
      "PkgName": "openssl",
      "InstalledVersion": "1.1.1",
      "FixedVersion": "1.1.1k",
      "Severity": "HIGH"
    }
  },
  "fabricated_fixtures": {
    "zero_findings": {"Results": []},
    "single_finding": {"Results": [{"Type": "vulnerabilities", "Vulnerabilities": [{}]}]},
    "multiple_findings": {"Results": [{"Type": "vulnerabilities", "Vulnerabilities": [{}, {}]}]}
  },
  "exit_code_patterns": {
    "0": "no vulnerabilities",
    "1": "vulnerabilities found"
  },
  "coverage_strategy": {
    "approach": "Equivalence partitioning",
    "test_count": 8,
    "categories": ["zero findings", "single finding", "multiple findings", "schema edge cases"]
  },
  "common_pitfalls": [
    "Trivy uses JSON array, not NDJSON",
    "exit code 1 is SUCCESS if findings exist",
    "Severity normalization: HIGH/CRITICAL/MEDIUM/LOW/UNKNOWN"
  ],
  "metadata": {
    "last_updated": "2025-10-24",
    "usage_count": 15,
    "success_rate": 0.92,
    "avg_time_saved_minutes": 45
  }
}
```

## Time Savings

40% faster repeated test writing (1-2 hours -> 0.6-1.2 hours)

## Example Workflow

1. **Query Memory:** Claude checks `.jmo/memory/test-patterns/trivy.json` before writing tests
2. **Cache Hit:** If cached, retrieve trivy test pattern instantly
   - Skip schema analysis (saves 15 min)
   - Skip coverage strategy design (saves 15 min)
   - Use proven fabricated fixtures (saves 15 min)
   - **Total Savings:** 45 min
3. **Cache Miss:** If not cached, analyze tool output and design tests (1-2 hours)
   - Analyze trivy JSON schema
   - Design coverage strategy (equivalence partitioning)
   - Create fabricated fixtures
   - Write 8 tests
4. **Store Result:** Save patterns for next adapter
5. **Next Time:** Use cached pattern (0.6-1.2 hours, 40% savings)

## Real-World Example: Writing Trivy Adapter Tests

**First Time (No Cache):**

```text
User: "Write tests for trivy_adapter.py"

Claude:
1. Analyzes trivy output schema (20 min)
   - Results[].Type, Results[].Vulnerabilities[]
   - Field mapping: VulnerabilityID, PkgName, Severity
2. Designs coverage strategy (15 min)
   - Equivalence partitioning: 0/1/many findings
3. Creates fabricated fixtures (20 min)
   - zero_findings.json, single_finding.json, multiple_findings.json
4. Writes 8 tests (25 min)
5. Achieves 89% coverage
6. STORES in .jmo/memory/test-patterns/trivy.json

Total: 1.5 hours
```

**Second Time (With Cache - Similar Tool):**

```text
User: "Write tests for syft_adapter.py"

Claude:
1. QUERIES .jmo/memory/test-patterns/trivy.json (instant)
   - Retrieves similar JSON schema pattern (SKIP analysis)
   - Retrieves coverage strategy (SKIP design)
2. Adapts trivy pattern for syft (30 min)
   - Syft uses same Results[] structure
   - Different fields (Artifacts instead of Vulnerabilities)
3. Writes 8 tests (20 min)
4. Achieves 87% coverage

Total: 50 min (44% savings)
```

## Benefits

- **Skip Schema Analysis:** Don't re-analyze JSON structure every time
- **Reuse Coverage Strategies:** Know which test categories to write
- **Proven Fixtures:** Use cached fabricated data that worked before
- **Avoid Pitfalls:** Remember NDJSON vs JSON array, exit code nuances
- **Consistent Coverage:** All adapters tested with same rigor (>=85%)

## Cache Management

```bash
# Review all cached test patterns
ls -lh .jmo/memory/test-patterns/

# Inspect specific pattern
cat .jmo/memory/test-patterns/trivy.json | jq '.'

# View test counts
cat .jmo/memory/test-patterns/*.json | jq -r '.tool + ": " + (.coverage_strategy.test_count | tostring)'

# Find most-used patterns
cat .jmo/memory/test-patterns/*.json | jq -r '.tool + ": " + (.metadata.usage_count | tostring)' | sort -t: -k2 -rn
```
