# Framework Version Updates

Procedures for tracking and updating compliance framework versions used by the compliance mapper.

## Current Framework Versions

**All frameworks current as of 2025-10-24:**

- OWASP Top 10: 2021 (current, next update: 2024 draft available, final 2025)
- CWE Top 25: 2024 (current, released June 2024, next: June 2025)
- CIS Controls: v8.1 (current, released May 2023, next: TBD 2025)
- NIST CSF: 2.0 (current, released February 2024, next: ~2027)
- PCI DSS: 4.0 (current, released March 2022, mandatory March 2025)
- MITRE ATT&CK: v15 (current Oct 2024, quarterly updates: Jan/Apr/Jul/Oct 2025)

## Update Schedule

- **Quarterly:** MITRE ATT&CK (check after each release)
- **Annually:** CWE Top 25 (June), check others for updates
- **As Announced:** OWASP Top 10, NIST CSF, CIS Controls, PCI DSS

## Memory Expiration Strategy

```json
{
  "framework_versions": {
    "owasp_top_10": "2021",
    "cwe_top_25": "2024",
    "cis_controls": "v8.1",
    "nist_csf": "2.0",
    "pci_dss": "4.0",
    "mitre_attack": "v15"
  },
  "last_verified": "2025-10-24",
  "expire_after_days": 90,
  "next_check": "2026-01-24"
}
```

## Quarterly Review Checklist

1. Check MITRE ATT&CK releases: https://attack.mitre.org/resources/updates/
2. Check CWE Top 25 (June only): https://cwe.mitre.org/top25/
3. Search for OWASP Top 10 updates: https://owasp.org/Top10/
4. Verify NIST CSF version: https://www.nist.gov/cyberframework
5. Check CIS Controls: https://www.cisecurity.org/controls
6. Check PCI DSS: https://www.pcisecuritystandards.org/

## Upgrade Path from v2.0.0

### For Existing Projects

1. **Run Bulk Mapping Script:**

```bash
# Map all CWEs found in findings
python3 scripts/dev/bulk_compliance_map.py results/summaries/findings.json
```

2. **Store in Memory:**

```bash
# Stores mappings in .jmo/memory/compliance/
# Future scans automatically use these mappings
```

### For New Projects

Use v2.1.0 workflow with memory integration from the start.
