# Compliance Report Examples

Reference examples for compliance report generation and output samples.

## Compliance Report Generation

### Generate Unified Compliance Report

**Output:** `COMPLIANCE_SUMMARY.md`

**Template:**

```markdown
# Compliance Summary

**Generated:** 2025-10-21 14:30:00
**Findings:** 150 total (45 HIGH, 72 MEDIUM, 33 LOW)
**Unique CWEs:** 12
**Memory Hits:** 10/12 (83%)

---

## OWASP Top 10 2021 Coverage

| Category | Count | Severity Distribution |
|----------|-------|-----------------------|
| A03:2021 (Injection) | 67 | 25 HIGH, 35 MEDIUM, 7 LOW |
| A01:2021 (Broken Access Control) | 23 | 10 HIGH, 10 MEDIUM, 3 LOW |
| A02:2021 (Cryptographic Failures) | 18 | 8 HIGH, 8 MEDIUM, 2 LOW |
| A06:2021 (Vulnerable Components) | 42 | 2 HIGH, 19 MEDIUM, 21 LOW |

**Compliance Status:** **NOT COMPLIANT** (45 HIGH findings require remediation)

---

## CWE Top 25 2024 Coverage

| Rank | CWE | Name | Count | Status |
|------|-----|------|-------|--------|
| 1 | CWE-89 | SQL Injection | 12 | HIGH risk |
| 2 | CWE-79 | XSS | 55 | HIGH risk |
| 5 | CWE-352 | CSRF | 8 | MEDIUM risk |
| 9 | CWE-918 | SSRF | 3 | LOW risk |

**Risk Score:** 287.5 (HIGH)

---

## PCI DSS 4.0 Compliance

| Requirement | Description | Findings | Status |
|-------------|-------------|----------|--------|
| 6.5.1 | SQL Injection | 12 | FAIL |
| 6.5.7 | XSS | 55 | FAIL |
| 6.5.9 | CSRF | 8 | WARNING |
| 11.6.1 | Change Detection | 0 | PASS |

**Compliance Status:** **FAIL** (Must remediate 6.5.1 and 6.5.7 before production)

---

## MITRE ATT&CK Techniques

| Tactic | Technique | Count | Mitigations |
|--------|-----------|-------|-------------|
| Initial Access | T1190 (Exploit Public-Facing App) | 55 | M1048, M1050 |
| Credential Access | T1552.001 (Credentials in Files) | 12 | M1047, M1027 |
| Execution | T1059 (Command Injection) | 20 | M1038, M1042 |

**Attack Surface:** 3 tactics, 8 techniques

---

## Recommendations

### Immediate (P1)

1. **Remediate CWE-89 (SQL Injection)** - 12 findings, PCI DSS requirement 6.5.1
2. **Remediate CWE-79 (XSS)** - 55 findings, PCI DSS requirement 6.5.7
3. **Implement WAF rules** - Block common injection patterns

### Short-Term (P2)

4. **Add CSRF tokens** - 8 findings, OWASP A01:2021
5. **Update vulnerable dependencies** - 42 findings, OWASP A06:2021

### Long-Term (P3)

6. **Implement security logging** - NIST CSF DE.CM-7
7. **Add SIEM integration** - CIS Control 8.11

---

**Memory Usage:** 10 CWEs from memory, 2 CWEs require manual mapping

**Next Steps:** Map CWE-434 and CWE-78 to complete coverage
```

## ATT&CK Navigator Export

Generate JSON for MITRE ATT&CK Navigator visualization:

```json
{
  "name": "CWE-79 XSS Attack Techniques",
  "versions": {
    "attack": "15.1",
    "navigator": "4.9.5",
    "layer": "4.5"
  },
  "domain": "enterprise-attack",
  "techniques": [
    {
      "techniqueID": "T1190",
      "score": 100,
      "color": "#ff6666",
      "comment": "XSS primary technique"
    },
    {
      "techniqueID": "T1552.001",
      "score": 75,
      "color": "#ff9999",
      "comment": "XSS can steal credentials"
    }
  ]
}
```
