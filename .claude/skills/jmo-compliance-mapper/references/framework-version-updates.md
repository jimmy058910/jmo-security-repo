# Framework Version Updates

Procedures for tracking and updating compliance framework versions used by the compliance mapper.

## Current Framework Versions

**These are the versions this mapper *emits*, not the newest releases upstream.**
The authority is [`scripts/core/compliance_frameworks.py`](../../../../scripts/core/compliance_frameworks.py)
— its module docstring lists all six, and the data below is copied from it:

| Framework | Version emitted | Where the code says so |
|-----------|-----------------|------------------------|
| OWASP Top 10 | 2021 | `CWE_TO_OWASP_TOP10_2021`; every category ID is `A01:2021`..`A10:2021` |
| CWE Top 25 | 2024 | `CWE_TOP_25_2024` |
| CIS Controls | v8.1 | module docstring |
| NIST CSF | 2.0 | module docstring |
| PCI DSS | 4.0 | module docstring |
| MITRE ATT&CK | v16.1 | module docstring + `# MITRE ATT&CK v16.1 Mappings` |

> **Do not "refresh" this table against upstream release notes.** Newer editions
> exist for several of these, but writing them here would only make the document
> disagree with the mapper. A framework version changes *here* when the mapping
> data changes in `compliance_frameworks.py` — the code moves first.

## Update Schedule

Upstream releases are the *trigger* to consider a code change, not a reason to
edit this file on its own:

- **Quarterly:** MITRE ATT&CK (check after each release)
- **Annually:** CWE Top 25 (June), check others for updates
- **As Announced:** OWASP Top 10, NIST CSF, CIS Controls, PCI DSS

When upstream moves, the work is: update the mappings in
`compliance_frameworks.py`, then update this table to match, then invalidate
cached records written under the old version.

## Memory Expiration Strategy

Records in `.jmo/memory/compliance/` carry the versions they were researched
against, so a record is stale when its `framework_versions` no longer match the
table above:

```json
{
  "framework_versions": {
    "owasp_top_10": "2021",
    "cwe_top_25": "2024",
    "cis_controls": "v8.1",
    "nist_csf": "2.0",
    "pci_dss": "4.0",
    "mitre_attack": "v16.1"
  },
  "last_verified": "2026-08-07",
  "expire_after_days": 90
}
```

**Compare against the code, not against a date.** A `next_check` field was
previously the only staleness signal here and it sat six months expired without
anything noticing, because nothing reads it. Diffing `framework_versions`
against `compliance_frameworks.py` is a check that cannot silently lapse.

## Quarterly Review Checklist

1. Check MITRE ATT&CK releases: https://attack.mitre.org/resources/updates/
2. Check CWE Top 25 (June only): https://cwe.mitre.org/top25/
3. Search for OWASP Top 10 updates: https://owasp.org/Top10/
4. Verify NIST CSF version: https://www.nist.gov/cyberframework
5. Check CIS Controls: https://www.cisecurity.org/controls
6. Check PCI DSS: https://www.pcisecuritystandards.org/

## Upgrade Path from v2.0.0

### For Existing Projects

**There is no bulk mapping script, and none is needed.** Compliance enrichment is
not an opt-in step — `jmo report` applies it to every finding automatically, in a
single pass over the deduplicated set:

```python
# scripts/core/normalize_and_report.py:234
deduped = enrich_findings_with_compliance(deduped)
```

So re-running the report is the whole upgrade path:

```bash
jmo report ./results
```

> A `scripts/dev/bulk_compliance_map.py` was documented here for several
> releases. It has never existed in this repository — `git ls-files` matches
> nothing for it. Adapters return raw findings and enrichment happens centrally;
> see the Enrichment Architecture section of [CLAUDE.md](../../../../CLAUDE.md).

### For New Projects

Use v2.1.0 workflow with memory integration from the start.
