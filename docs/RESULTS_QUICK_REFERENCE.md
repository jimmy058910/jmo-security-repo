# JMo Security Results Quick Reference

*One-page guide to triage your scan results in 30 minutes*

> **📖 Need more detail?** See [RESULTS_GUIDE.md](RESULTS_GUIDE.md) for the complete 12,000-word guide.

---

## Step 1: Start with the Summary (2 minutes)

```bash
cat results/summaries/SUMMARY.md
```text
**Look for:**

- Total CRITICAL + HIGH count (your immediate priority)
- Top files (where are the issues?)
- Top tools (what found what?)

**Example:**
```text
Total: 8058 | 🔴 3 CRITICAL | 🔴 91 HIGH | 🟡 280 MEDIUM
```text
**Translation:** 94 findings to review (not 8058)

---

## Step 2: Filter Production Code (5 minutes)

```bash

# Extract only CRITICAL + HIGH in production code

jq '[.[] | select(.severity == "CRITICAL" or .severity == "HIGH")
         | select(.location.path | contains("tests/") or contains(".venv/") or contains("fixtures/") | not)]' \
  results/summaries/findings.json > priority.json

# Count them

jq 'length' priority.json
```text
**Common patterns to ignore:**

- `.venv/`, `node_modules/` → Dependencies (not your code)
- `tests/fixtures/` → Test data (intentional vulnerabilities)
- `samples/`, `examples/` → Demo code

---

## Step 3: Group by Rule (10 minutes)

```bash

# Find systemic issues (same rule ID repeated)

jq 'group_by(.ruleId) | map({rule: .[0].ruleId, count: length, severity: .[0].severity})
    | sort_by(.count) | reverse | .[0:10]' priority.json
```text
**Why:** Fixing 1 root cause can eliminate 50+ findings

**Example:**
```json
[
  {"rule": "CVE-2023-12345", "count": 50, "severity": "HIGH"}
]
```text
**Fix:** One `pip install --upgrade vulnerable-package` fixes all 50

---

## Step 4: Check False Positives (10 minutes)

| Tool | Rule | False Positive? | How to Verify |
|------|------|-----------------|---------------|
| Bandit | B101 | ✅ Yes (in test files) | Path contains `test` |
| Bandit | B411 | ✅ Yes (in PyPI packages) | Path is `.venv/lib/python3.X/site-packages/` |
| Semgrep | `run-shell-injection` | ✅ Yes (GHA echo) | Check it's not in script execution |
| TruffleHog | Generic secrets | ⚠️ Maybe | Look for comments `# Example (not real)` |
| Trivy | CVE in test deps | ⚠️ Maybe | Check if imported in production |

**Quick check for Bandit B101 in tests:**
```bash
jq '[.[] | select(.ruleId == "B101" and (.location.path | contains("test")))] | length' priority.json
```text
---

## Step 5: Suppress Noise (3 minutes)

**Create `jmo.suppress.yml`:**

```yaml
suppressions:
  # Third-party dependencies

  - path: ".venv/*"
    reason: "Third-party PyPI packages"

  # Test fixtures

  - path: "tests/fixtures/*"
    reason: "Intentional vulnerabilities for testing"

  # Specific false positives

  - ruleId: "B101"

    reason: "pytest uses assert extensively"
```text
**Re-run scan to verify:**
```bash
jmotools balanced --repos-dir .
cat results/summaries/SUPPRESSIONS.md
```text
---

## Common Queries (Copy-Paste)

### Find All Secrets

```bash
jq '[.[] | select(.tags[]? == "secret")]' results/summaries/findings.json
```text

### Find Exploitable CVEs (CVSS ≥7.0)

```bash
jq '[.[] | select(.cvss? and (.cvss.score >= 7.0))]' results/summaries/findings.json
```text

### Find SQL Injection

```bash
jq '[.[] | select(.ruleId | contains("sql") or (.message | ascii_downcase | contains("sql injection")))]' results/summaries/findings.json
```text

### Get OWASP A03 (Injection) Findings

```bash
jq '[.[] | select(.compliance.owaspTop10_2021[]? == "A03:2021")]' results/summaries/findings.json
```text

### Group by File

```bash
jq 'group_by(.location.path) | map({file: .[0].location.path, count: length})
    | sort_by(.count) | reverse | .[0:20]' results/summaries/findings.json
```text
---

## Triage Decision Tree

```text
Is it CRITICAL or HIGH?
  NO → Defer to next sprint
  YES → Continue...

Is it in production code?
  NO → Is it in dependencies?
    YES → Check if exploitable in prod
    NO → Is it a test fixture?
      YES → Suppress
      NO → Review CI/CD hardening
  YES → Continue...

Is it a systemic issue (50+ occurrences)?
  YES → Fix root cause (1 fix = 50+ resolved)
  NO → Continue...

Is it a false positive?
  YES → Add to jmo.suppress.yml
  NO → FIX IMMEDIATELY
```text
---

## File Quick Reference

| File | Use When |
|------|----------|
| `SUMMARY.md` | First look, triage priorities |
| `dashboard.html` | Deep investigation, filtering |
| `findings.json` | Scripting, custom analysis |
| `findings.sarif` | GitHub/GitLab Security tab |
| `COMPLIANCE_SUMMARY.md` | Compliance audits |
| `PCI_DSS_COMPLIANCE.md` | Payment compliance |
| `attack-navigator.json` | Threat modeling |

---

## Compliance Quick Reference

| Framework | When to Use | Key Output |
|-----------|-------------|------------|
| **OWASP Top 10** | Web app security audits | A03:2021 = Injection, A02:2021 = Crypto |
| **CWE Top 25** | Secure coding standards | CWE-798 = Hardcoded Credentials |
| **NIST CSF 2.0** | Enterprise risk management | PROTECT/DETECT/GOVERN functions |
| **PCI DSS 4.0** | Payment processing apps | Requirement 6.2.4 = Code scanning |
| **CIS Controls** | Cyber insurance | IG1 (basic) → IG3 (advanced) |
| **MITRE ATT&CK** | Threat modeling | T1195 = Supply Chain Compromise |

---

## Severity Definitions

| Level | Meaning | Example | Action |
|-------|---------|---------|--------|
| **CRITICAL** | Immediate security risk | Hardcoded passwords, RCE | Fix immediately |
| **HIGH** | Serious issue | SQL injection, XSS, CVE ≥7.0 | Fix within 1 week |
| **MEDIUM** | Moderate risk | Weak crypto, missing auth | Fix within 1 month |
| **LOW** | Minor issue | Info disclosure | Fix when convenient |
| **INFO** | Informational | Deprecated APIs | Optional |

---

## CI/CD Integration (30 seconds)

**GitHub Actions:**
```yaml

- name: Security Scan
  run: docker run --rm -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan

- name: Gate on HIGH/CRITICAL

    HIGH_COUNT=$(jq '[.[] | select(.severity == "HIGH" or .severity == "CRITICAL")] | length' results/summaries/findings.json)
    [ "$HIGH_COUNT" -eq 0 ] || exit 1

- name: Upload SARIF

  with:
    sarif_file: results/summaries/findings.sarif
```text
---

## Troubleshooting

**Issue:** Too many LOW findings, can't find real issues
**Fix:** Filter aggressively (see Step 2 above)

**Issue:** Same CVE appears 50 times
**Fix:** Group by ruleId (see Step 3 above) - one fix resolves all

**Issue:** Dashboard won't open
**Fix:** Use local web server: `cd results/summaries && python3 -m http.server 8000`

---

## Get Help

- **Full Guide:** [docs/RESULTS_GUIDE.md](RESULTS_GUIDE.md)
- **User Guide:** [docs/USER_GUIDE.md](USER_GUIDE.md)
- **Issues:** <https://github.com/jimmy058910/jmo-security-repo/issues>
- **Discussions:** <https://github.com/jimmy058910/jmo-security-repo/discussions>

---

*Print this card and keep it handy during triage sessions*
