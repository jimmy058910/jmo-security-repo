---
name: jmo-compliance-mapper
description: Map security findings to 6 compliance frameworks (OWASP, CWE, CIS, NIST, PCI DSS, MITRE ATT&CK) with memory-integrated patterns. Use when asked about compliance mappings or framework coverage.
argument-hint: <CWE-ID or tool-name>
user-invocable: true
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

## Execution

Map compliance for: **$ARGUMENTS**

---

## Purpose

**Approach:** Map with precision and cite sources. Every framework mapping must reference the specific standard clause.

---

## What's New in v2.1.0

### Memory Integration Features

1. **Query-Before-Map Pattern** - Check `.jmo/memory/compliance/{cwe}.json` before research. Reuse known framework mappings. **Time Savings:** 15-25 min if CWE already mapped.

2. **Store-After-Mapping Pattern** - Store CWE mappings for future reuse. Track confidence and last update date.

3. **Bulk Memory Queries** - Query multiple CWEs in single operation. Pre-populate compliance fields during reporting.

4. **Auto-Update Detection** - Track OWASP/CWE/NIST version changes. Flag stale mappings for re-validation.

For full memory query/store code, bulk enrichment workflows, and example payloads, see [references/memory-integration.md](references/memory-integration.md).

---

## Skill Invocation

### Natural Language Triggers

**Direct Actions:**

- "Map {CWE} to compliance frameworks"
- "What frameworks does {CWE} map to?"
- "Generate compliance report for {CWE-list}"

**Problem Statements:**

- "Need PCI DSS mapping for {vulnerability}"
- "Which OWASP category is {CWE}?"
- "Show me MITRE ATT&CK techniques for {CWE}"

**Context Clues:**

- Mentions of CWE IDs (CWE-79, CWE-89, etc.)
- References to frameworks (OWASP, NIST, PCI DSS)
- Compliance audit or reporting tasks

---

## Skill Workflow (6 Phases)

### Phase 0: Memory Query (v2.1.0)

Check if CWE mapping already stored. On memory hit (fresh), skip all research (0-2 min). On memory hit (stale, >6 months), quick refresh (5-10 min). On miss, full research (30-40 min).

See [references/memory-integration.md](references/memory-integration.md) for query code and example memory hit payloads.

---

### Phase 1: CWE Research

**Purpose:** Understand CWE definition and characteristics

**Actions:**

1. **Query CWE Database:** https://cwe.mitre.org/data/definitions/{id}.html - Extract name, description, consequences, mitigations
2. **Identify Related CWEs:** Parent CWEs (e.g., CWE-79 -> CWE-20), child CWEs
3. **Document Common Exploits:** Real-world examples, CAPEC mappings

**Example (CWE-79):**

```yaml
cwe: CWE-79
name: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
parent_cwe: CWE-20  # Improper Input Validation
capec:
  - CAPEC-18  # XSS Targeting Non-Script Elements
  - CAPEC-86  # XSS Through Log Files
common_consequences:
  - Confidentiality: Read application data
  - Integrity: Execute unauthorized code or commands
  - Access Control: Bypass protection mechanism
```

---

### Phase 2: OWASP Top 10 2021 Mapping

**Purpose:** Map CWE to OWASP categories

| OWASP Category | Description | Common CWEs |
|----------------|-------------|-------------|
| A01:2021 | Broken Access Control | CWE-200, CWE-201, CWE-352 |
| A02:2021 | Cryptographic Failures | CWE-261, CWE-296, CWE-327 |
| A03:2021 | Injection | CWE-79, CWE-89, CWE-94 |
| A04:2021 | Insecure Design | CWE-209, CWE-256, CWE-501 |
| A05:2021 | Security Misconfiguration | CWE-16, CWE-611, CWE-776 |
| A06:2021 | Vulnerable and Outdated Components | CWE-1104, CWE-937 |
| A07:2021 | Identification and Authentication Failures | CWE-287, CWE-384 |
| A08:2021 | Software and Data Integrity Failures | CWE-502, CWE-829 |
| A09:2021 | Security Logging and Monitoring Failures | CWE-117, CWE-778 |
| A10:2021 | Server-Side Request Forgery (SSRF) | CWE-918 |

Store mapping in `.jmo/memory/compliance/CWE-{id}.json` with framework version for staleness detection.

---

### Phase 3: CWE Top 25 2024 Mapping

**Purpose:** Determine CWE ranking and category

**Top 10 CWEs (2024):**

1. CWE-89: SQL Injection (score: 46.9)
2. CWE-79: Cross-Site Scripting (score: 45.5)
3. CWE-787: Out-of-bounds Write (score: 44.5)
4. CWE-22: Path Traversal (score: 43.2)
5. CWE-352: CSRF (score: 41.8)
6. CWE-434: Unrestricted Upload (score: 40.3)
7. CWE-862: Missing Authorization (score: 39.1)
8. CWE-78: OS Command Injection (score: 37.6)
9. CWE-918: SSRF (score: 36.2)
10. CWE-119: Buffer Errors (score: 35.4)

Output includes rank, category, score, previous rank, and trend.

---

### Phase 4: CIS, NIST, PCI DSS Mapping

**Purpose:** Map to operational security frameworks

**CIS Controls v8.1** - Map to control ID, title, implementation group (IG1/IG2/IG3), and safeguards. Example: CWE-79 maps to Control 16.11 (Leverage Vetted Modules for App Security, IG2).

**NIST Cybersecurity Framework 2.0** - Map to function (ID/PR/DE/RS/RC), category, subcategory, and informative references. Example: CWE-79 maps to PR.DS-5 (Protections against data leaks).

**PCI DSS 4.0** - Map to requirement, description, priority (P1/P2/P3), and testing procedures. Example: CWE-79 maps to Requirement 6.5.7 (Cross-site scripting, P1).

---

### Phase 5: MITRE ATT&CK Mapping

**Purpose:** Map to adversary tactics and techniques (ATT&CK for Enterprise v15.1)

Map each CWE to tactics (e.g., TA0001 Initial Access), techniques (e.g., T1190), subtechniques, data sources, and mitigations. Example: CWE-79 maps to T1190 (Exploit Public-Facing Application) and T1552.001 (Credentials In Files).

---

### Phase 6: Store Memory (v2.1.0)

Persist complete compliance mappings to `.jmo/memory/compliance/{cwe_id}.json` for future reuse. See [references/memory-integration.md](references/memory-integration.md) for store code.

---

## Bulk Compliance Enrichment

For enriching all findings in a scan report, use the memory-integrated bulk approach. Extracts unique CWEs, queries memory for each, enriches findings, and reports hit/miss statistics.

**Time savings:** 2-5 min (all memory hits) vs. 300 min (sequential research per CWE) -- 98% reduction.

Full bulk enrichment code and sequential vs. memory-integrated comparison: [references/memory-integration.md](references/memory-integration.md).

---

## Compliance Report Generation

Generate unified `COMPLIANCE_SUMMARY.md` covering OWASP Top 10 coverage, CWE Top 25 risk scoring, PCI DSS pass/fail status, MITRE ATT&CK attack surface, and prioritized remediation recommendations.

For full report template, output samples, and ATT&CK Navigator export JSON, see [examples/compliance-report-examples.md](examples/compliance-report-examples.md).

---

## Time Savings Comparison

### v2.0.0 (Non-Memory)

| Phase | Duration (per CWE) |
|-------|--------------------|
| CWE Research (Phase 1) | 10 min |
| OWASP Mapping (Phase 2) | 5 min |
| CWE Top 25 (Phase 3) | 5 min |
| CIS/NIST/PCI (Phase 4) | 10 min |
| MITRE ATT&CK (Phase 5) | 10 min |
| **Total per CWE** | **40 min** |

**Example:** 10 unique CWEs = 400 min (6.7 hours)

### v2.1.0 (Memory-Integrated)

| Scenario | Duration | Savings |
|----------|----------|---------|
| **Memory Hit (Fresh)** | 2 min | 38 min (95%) |
| **Memory Hit (Stale)** | 10 min | 30 min (75%) |
| **Memory Miss** | 40 min | 0 min (baseline) |

**Example:** 10 CWEs (8 hits, 2 misses) = 8x2 + 2x40 = 96 min (1.6 hours). **Savings:** 304 min (76%).

---

## Framework Version Updates

All 6 frameworks tracked with quarterly review cadence and memory expiration strategy. For current versions, update schedule, quarterly review checklist, and upgrade path from v2.0.0, see [references/framework-version-updates.md](references/framework-version-updates.md).
