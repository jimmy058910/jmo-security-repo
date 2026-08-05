# Memory Integration for Compliance Mapper

Detailed memory query/store patterns and bulk enrichment workflows for compliance mappings.

## Phase 0: Memory Query

**Purpose:** Check if CWE mapping already stored before performing full research.

```python
from scripts.core.memory import query_memory

def check_compliance_memory(cwe_id: str) -> dict | None:
    """
    Query memory for existing compliance mappings.

    Args:
        cwe_id: CWE identifier (e.g., "CWE-79")

    Returns:
        Compliance mapping dict if found, None otherwise
    """
    memory_data = query_memory("compliance", cwe_id)

    if memory_data:
        print(f"[memory] Found mappings for {cwe_id}")
        print(f"[memory] Last updated: {memory_data.get('last_updated')}")

        # Check if mapping is stale (>6 months old)
        from datetime import datetime, timedelta
        last_updated = datetime.fromisoformat(memory_data.get("last_updated"))
        if datetime.now() - last_updated > timedelta(days=180):
            print(f"[memory] Mapping is stale (>6 months), recommend refresh")

        return memory_data

    print(f"[memory] No mapping for {cwe_id}, running full research")
    return None
```

## Example Memory Hit

```json
{
  "cwe": "CWE-79",
  "name": "Cross-Site Scripting (XSS)",
  "frameworks": {
    "owasp_top_10_2021": ["A03:2021"],
    "cwe_top_25_2024": { "rank": 2, "category": "Injection", "score": 45.5 },
    "cis_controls_v8_1": [
      { "control": "16.11", "title": "Leverage Vetted Modules or Services for Application Security", "implementation_group": "IG2" }
    ],
    "nist_csf_2_0": [
      { "function": "PR", "category": "PR.DS", "subcategory": "PR.DS-5", "description": "Protections against data leaks are implemented" }
    ],
    "pci_dss_4_0": [
      { "requirement": "6.5.7", "description": "Cross-site scripting (XSS)", "priority": "P1" }
    ],
    "mitre_attack": [
      { "tactic": "TA0001", "tactic_name": "Initial Access", "technique": "T1190", "technique_name": "Exploit Public-Facing Application" }
    ]
  },
  "confidence": "high",
  "last_updated": "2025-09-15",
  "framework_versions": {
    "owasp": "2021", "cwe_top_25": "2024", "cis": "8.1", "nist_csf": "2.0", "pci_dss": "4.0"
  },
  "created_by": "jmo-compliance-mapper v2.1.0"
}
```

## Phase 6: Store Memory

**Purpose:** Persist compliance mappings for future reuse.

```python
from scripts.core.memory import store_memory
from datetime import datetime

def store_compliance_mapping(cwe_id: str, mappings: dict):
    """Store CWE compliance mappings in memory."""
    memory_data = {
        "cwe": cwe_id,
        "name": mappings.get("name"),
        "frameworks": {
            "owasp_top_10_2021": mappings.get("owasp", []),
            "cwe_top_25_2024": mappings.get("cwe_top_25", {}),
            "cis_controls_v8_1": mappings.get("cis", []),
            "nist_csf_2_0": mappings.get("nist", []),
            "pci_dss_4_0": mappings.get("pci", []),
            "mitre_attack": mappings.get("attack", [])
        },
        "confidence": "high",
        "last_updated": datetime.now().isoformat(),
        "framework_versions": {
            "owasp": "2021", "cwe_top_25": "2024", "cis": "8.1",
            "nist_csf": "2.0", "pci_dss": "4.0", "mitre_attack": "15.1"
        },
        "created_by": "jmo-compliance-mapper v2.1.0"
    }

    store_memory("compliance", cwe_id, memory_data)
    print(f"[memory] Stored mappings for {cwe_id}")
    print(f"[memory] Location: .jmo/memory/compliance/{cwe_id}.json")
```

**Memory File Location:** `.jmo/memory/compliance/{cwe_id}.json`

## Bulk Compliance Enrichment

### Use Case: Enrich All Findings in Report

**Problem:** Scan produced 150 findings, need compliance mappings for all CWEs.

**Memory-Integrated Approach:**

```python
from scripts.core.memory import query_memory, store_memory

def enrich_findings_with_compliance(findings: list) -> list:
    """Enrich findings with compliance mappings from memory."""
    # Extract unique CWEs
    unique_cwes = set()
    for finding in findings:
        cwes = finding.get("raw", {}).get("cwe", [])
        unique_cwes.update(cwes)

    print(f"[compliance] Found {len(unique_cwes)} unique CWEs")

    # Query memory for each CWE
    compliance_cache = {}
    for cwe in unique_cwes:
        memory_data = query_memory("compliance", cwe)
        if memory_data:
            print(f"[memory] Hit: {cwe}")
            compliance_cache[cwe] = memory_data.get("frameworks")
        else:
            print(f"[memory] Miss: {cwe} - needs mapping")
            compliance_cache[cwe] = None

    # Enrich findings
    for finding in findings:
        cwes = finding.get("raw", {}).get("cwe", [])
        compliance = {}
        for cwe in cwes:
            if compliance_cache.get(cwe):
                compliance[cwe] = compliance_cache[cwe]
        finding["compliance"] = compliance

    # Report statistics
    hits = sum(1 for v in compliance_cache.values() if v is not None)
    misses = len(compliance_cache) - hits
    print(f"[memory] Hits: {hits}/{len(unique_cwes)} ({hits/len(unique_cwes)*100:.0f}%)")
    print(f"[memory] Misses: {misses} (need manual mapping)")

    return findings

# Time: 2-5 min (all memory hits) vs. 300 min (sequential research)
# Savings: 295 min (98%)
```

**Benefits:**

1. **Speed:** Instant retrieval for known CWEs
2. **Consistency:** Same CWE always mapped identically
3. **Partial Results:** Use known mappings, defer unknown CWEs
4. **Incremental Improvement:** Each manual mapping benefits future scans
