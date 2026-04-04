# Memory Integration

**Memory Namespace:** `.jmo/memory/security/`

---

## What's Stored

- **OWASP Fixes:** CSRF tokens, XSS sanitization, SQL injection prevention, security headers
- **CWE Remediation Patterns:** Mapped by CWE ID (e.g., CWE-79 -> XSS fixes, CWE-89 -> SQLi prevention)
- **Security Testing:** Test patterns for each vulnerability type (fuzzing, boundary testing, negative cases)
- **Framework-Specific Implementations:** Flask/Django CSRF, FastAPI security headers, etc.
- **Compliance Mappings:** Which OWASP Top 10 / CWE Top 25 requirements each fix addresses

## Query Before Analysis

```bash
# Check if CSRF protection pattern cached
cat .jmo/memory/security/csrf-protection.json | jq '.implementation'

# Check if XSS sanitization pattern cached
cat .jmo/memory/security/xss-sanitization.json | jq '.libraries'

# Check if path traversal fix pattern cached
cat .jmo/memory/security/path-traversal.json | jq '.sanitization_function'
```

## Storage Format (JSON)

```json
{
  "vulnerability": "csrf-protection",
  "cwe_id": "CWE-352",
  "owasp_category": "A01:2021 - Broken Access Control",
  "fix_pattern": {
    "framework": "Flask",
    "implementation": [
      "from flask_wtf.csrf import CSRFProtect",
      "csrf = CSRFProtect()",
      "csrf.init_app(app)"
    ],
    "template_changes": [
      "Add {{ csrf_token() }} to all forms"
    ]
  },
  "test_patterns": {
    "positive_test": "def test_csrf_token_generated(): assert 'csrf_token' in session",
    "negative_test": "def test_csrf_missing_blocks_request(): assert response.status_code == 403",
    "edge_cases": [
      "test_csrf_token_rotation",
      "test_csrf_double_submit_cookie",
      "test_csrf_ajax_requests"
    ]
  },
  "common_pitfalls": [
    "Forgetting to exempt AJAX endpoints",
    "Not rotating tokens after login",
    "Missing CSRF for state-changing GET requests"
  ],
  "metadata": {
    "last_updated": "2025-10-24",
    "usage_count": 12,
    "success_rate": 0.98,
    "avg_time_saved_hours": 2.0
  }
}
```

## Time Savings

45% faster repeated security fixes (2-6 hours -> 1.1-3.3 hours)

## Workflow

1. **Check Memory First:** Is `.jmo/memory/security/<vulnerability>.json` cached?
2. **If Yes (Cache Hit):**
   - Retrieve fix pattern, sanitization function, test patterns (instant)
   - Skip OWASP research (20 min), implementation discovery (30 min), test design (30 min)
   - **Total Time:** 1.1-1.5 hours (60% savings)
3. **If No (Cache Miss):**
   - Research CWE (20 min), design approach (30 min), implement (45 min), write tests (2 hours), validate (15 min)
   - Store in Memory for next time
   - **Total Time:** 3.5-4 hours

## CWE -> Framework Mapping (Cached)

Memory stores which CWEs map to which compliance frameworks:

```json
{
  "cwe_79": {
    "name": "Cross-Site Scripting (XSS)",
    "owasp_top10_2021": "A03:2021 - Injection",
    "cwe_top25_2024": { "rank": 2 },
    "nist_csf_2_0": "PR.DS-5",
    "pci_dss_4_0": "6.5.7",
    "mitre_attack": ["T1189 - Drive-by Compromise"]
  }
}
```

## Security Test Templates (Cached)

```json
{
  "vulnerability_type": "path_traversal",
  "test_templates": {
    "fuzzing": { "count": 100, "pattern": "test_sanitize_random_char_{i}" },
    "unit": { "count": 15, "examples": ["test_sanitize_empty_string", "test_sanitize_whitespace"] },
    "negative": { "count": 8, "examples": ["test_sanitize_traversal_sequences", "test_sanitize_absolute_paths"] }
  }
}
```

## Cached Fix Files

```text
.jmo/memory/security/csrf-protection.json
.jmo/memory/security/xss-sanitization.json
.jmo/memory/security/sql-injection.json
.jmo/memory/security/path-traversal.json
.jmo/memory/security/security-headers.json
.jmo/memory/security/command-injection.json
.jmo/memory/security/authentication.json
.jmo/memory/security/session-management.json
```

## Cache Management

```bash
# Review all cached security fixes
ls -lh .jmo/memory/security/

# View success rates
cat .jmo/memory/security/*.json | jq -r '.vulnerability + ": " + (.metadata.success_rate | tostring)'

# Invalidate outdated fix (e.g., Flask 3.x changes CSRF API)
rm .jmo/memory/security/csrf-protection.json
```

## Cache Invalidation

- **Manual:** Delete `.jmo/memory/security/<file>.json` to force fresh analysis
- **Automatic:** Cache expires after 365 days (OWASP patterns change annually)
- **Framework Change:** Invalidate when framework version changes significantly
