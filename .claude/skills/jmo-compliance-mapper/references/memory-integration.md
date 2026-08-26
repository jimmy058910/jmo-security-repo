# Memory Integration for Compliance Mapper

Detailed memory query/store patterns and bulk enrichment workflows for compliance mappings.

## Phase 0: Memory Query

**Purpose:** Check if CWE mapping already stored before performing full research.

> There is no `scripts.core.memory` module. `.jmo/memory/` is a **file
> convention**, not a Python API — see
> [memory-integration-pattern.md](../../references/memory-integration-pattern.md).
> Each skill reads and writes the JSON itself, so these examples use the stdlib.

```python
import json
import re
from datetime import datetime, timedelta
from pathlib import Path

MEMORY_ROOT = Path(".jmo/memory/compliance")
MAX_AGE = timedelta(days=180)  # 6 months
CWE_RE = re.compile(r"^CWE-[0-9]{1,6}$")


def memory_path(cwe_id: str) -> Path:
    """Resolve a CWE id to its memory file, rejecting traversal (CWE-22)."""
    if not CWE_RE.match(cwe_id):
        raise ValueError(f"not a CWE identifier: {cwe_id!r}")
    return MEMORY_ROOT / f"{cwe_id}.json"


def check_compliance_memory(cwe_id: str) -> dict | None:
    """
    Query memory for existing compliance mappings.

    Args:
        cwe_id: CWE identifier (e.g., "CWE-79")

    Returns:
        The mapping if a usable, current record exists; None otherwise.
        None always means "do the full research" -- a caller never has to
        distinguish absent from unusable.
    """
    path = memory_path(cwe_id)
    try:
        memory_data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"[memory] No mapping for {cwe_id}, running full research")
        return None
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[memory] Unreadable record for {cwe_id} ({exc}); treating as miss")
        return None

    # A missing key yields None and a hand-edited value can be anything, so
    # both TypeError and ValueError are expected here -- neither is fatal.
    try:
        last_updated = datetime.fromisoformat(memory_data["last_updated"])
    except (KeyError, TypeError, ValueError):
        print(f"[memory] {cwe_id} has no usable timestamp; treating as miss")
        return None

    age = datetime.now() - last_updated
    if age > MAX_AGE:
        print(f"[memory] {cwe_id} is stale ({age.days}d > {MAX_AGE.days}d); re-researching")
        return None

    print(f"[memory] Hit: {cwe_id} (updated {memory_data['last_updated']})")
    return memory_data
```

**Stale records are a miss, not a hit.** Returning the record alongside a
"recommend refresh" message leaves the decision to a caller that has no reason
to re-check it, so a mapping researched against OWASP 2021 keeps being served
after the framework moves. Returning `None` makes the refresh happen.

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
    "owasp": "2021", "cwe_top_25": "2024", "cis": "8.1",
    "nist_csf": "2.0", "pci_dss": "4.0", "mitre_attack": "16.1"
  },
  "created_by": "jmo-compliance-mapper v2.1.0"
}
```

## Phase 6: Store Memory

**Purpose:** Persist compliance mappings for future reuse.

```python
import json
from datetime import datetime

# Every framework the mapper is expected to resolve. Anything missing or empty
# means the record is partial, which is what decides confidence below.
REQUIRED_FRAMEWORKS = (
    "owasp_top_10_2021",
    "cwe_top_25_2024",
    "cis_controls_v8_1",
    "nist_csf_2_0",
    "pci_dss_4_0",
    "mitre_attack",
)


def store_compliance_mapping(
    cwe_id: str,
    mappings: dict,
    confidence: str | None = None,
    evidence: list[str] | None = None,
) -> None:
    """Store CWE compliance mappings in memory.

    Args:
        cwe_id: CWE identifier, e.g. "CWE-79".
        mappings: Per-framework results from the mapping workflow.
        confidence: "high" only when the workflow verified every framework
            against its published source. Left unset, it is derived below --
            never assumed.
        evidence: Citations backing the mapping; an empty list caps confidence.
    """
    frameworks = {
        "owasp_top_10_2021": mappings.get("owasp", []),
        "cwe_top_25_2024": mappings.get("cwe_top_25", {}),
        "cis_controls_v8_1": mappings.get("cis", []),
        "nist_csf_2_0": mappings.get("nist", []),
        "pci_dss_4_0": mappings.get("pci", []),
        "mitre_attack": mappings.get("attack", []),
    }

    if confidence is None:
        resolved = sum(1 for key in REQUIRED_FRAMEWORKS if frameworks.get(key))
        if resolved == len(REQUIRED_FRAMEWORKS) and evidence:
            confidence = "high"
        elif resolved:
            confidence = "partial"
        else:
            confidence = "unverified"

    memory_data = {
        "cwe": cwe_id,
        "name": mappings.get("name"),
        "frameworks": frameworks,
        "confidence": confidence,
        "evidence": evidence or [],
        "unresolved": [k for k in REQUIRED_FRAMEWORKS if not frameworks.get(k)],
        "last_updated": datetime.now().isoformat(),
        "framework_versions": {
            "owasp": "2021", "cwe_top_25": "2024", "cis": "8.1",
            "nist_csf": "2.0", "pci_dss": "4.0", "mitre_attack": "16.1"
        },
        "created_by": "jmo-compliance-mapper",
    }

    path = memory_path(cwe_id)  # validates the id; see Phase 0
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(memory_data, indent=2), encoding="utf-8")
    print(f"[memory] Stored {cwe_id} (confidence={confidence})")
    print(f"[memory] Location: {path}")
```

**Confidence is derived, never assumed.** Writing `"high"` unconditionally made
the field meaningless: a record with five empty frameworks and no citation was
indistinguishable from a fully-researched one, so nothing downstream could
choose to re-research. `unresolved` records *which* frameworks are missing, so
a later pass can fill only the gaps.

**Memory File Location:** `.jmo/memory/compliance/{cwe_id}.json`

## Bulk Compliance Enrichment

### Use Case: Enrich All Findings in Report

**Problem:** Scan produced 150 findings, need compliance mappings for all CWEs.

**Memory-Integrated Approach:**

> **Do not name this `enrich_findings_with_compliance`.** That name is taken by
> real production code — `scripts/core/compliance_mapper.py:1278`, called from
> `normalize_and_report.py:234` during the report phase. It maps from the
> built-in tables, not from `.jmo/memory/`. This helper is a *research* aid for
> the skill; giving it the production name invites someone to wire the wrong one
> into the pipeline.

```python
def preview_memory_coverage(findings: list) -> dict:
    """Report which findings' CWEs already have researched mappings.

    Read-only: it tells the mapper what is left to research. Report-phase
    enrichment stays in compliance_mapper.enrich_findings_with_compliance().
    """
    # Extract unique CWEs
    unique_cwes = set()
    for finding in findings:
        cwes = finding.get("raw", {}).get("cwe", [])
        unique_cwes.update(cwes)

    print(f"[compliance] Found {len(unique_cwes)} unique CWEs")

    # Query memory for each CWE
    compliance_cache = {}
    for cwe in unique_cwes:
        memory_data = check_compliance_memory(cwe)
        if memory_data:
            print(f"[memory] Hit: {cwe}")
            compliance_cache[cwe] = memory_data.get("frameworks")
        else:
            print(f"[memory] Miss: {cwe} - needs mapping")
            compliance_cache[cwe] = None

    # Report statistics. Plenty of scans produce no CWE-bearing findings at all
    # (a clean run, or tools that emit only rule ids), so the empty set is a
    # normal input -- not a reason to raise ZeroDivisionError on the last line.
    hits = sum(1 for v in compliance_cache.values() if v is not None)
    total = len(unique_cwes)
    misses = total - hits
    pct = (hits / total * 100) if total else 0.0
    print(f"[memory] Hits: {hits}/{total} ({pct:.0f}%)")
    print(f"[memory] Misses: {misses} (need manual mapping)")

    return {
        "unique_cwes": total,
        "hits": hits,
        "misses": misses,
        "needs_research": sorted(c for c, v in compliance_cache.items() if v is None),
    }
```

**Benefits:**

1. **Speed:** Instant retrieval for known CWEs
2. **Consistency:** Same CWE always mapped identically
3. **Partial Results:** Research only what `needs_research` lists
4. **Incremental Improvement:** Each manual mapping benefits future scans
