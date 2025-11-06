# Security Diff Workflows

This guide provides practical workflows for using `jmo diff` in common development scenarios.

## Table of Contents

- [Use Case 1: PR Review Comments](#use-case-1-pr-review-comments)
- [Use Case 2: CI/CD Security Gate](#use-case-2-cicd-security-gate)
- [Use Case 3: Sprint Tracking](#use-case-3-sprint-tracking)
- [Use Case 4: Release Validation](#use-case-4-release-validation)
- [Use Case 5: Historical Trend Analysis](#use-case-5-historical-trend-analysis)
- [Advanced Workflows](#advanced-workflows)
- [Troubleshooting](#troubleshooting)

---

## Use Case 1: PR Review Comments

**Goal:** Automatically comment on pull requests with security diff reports, showing only NEW issues introduced by the PR.

### Workflow

```mermaid
graph LR
    A[PR Opened] --> B[Scan Main Branch]
    B --> C[Scan PR Branch]
    C --> D[Generate Diff]
    D --> E[Post PR Comment]
    E --> F[Upload SARIF]
```

### Implementation

**GitHub Actions:** See [github-actions-diff.yml](github-actions-diff.yml)

**GitLab CI:** See [gitlab-ci-diff.yml](gitlab-ci-diff.yml)

### Benefits

- ✅ **Immediate feedback:** Developers see new findings without leaving GitHub/GitLab
- ✅ **Reduced noise:** Only shows changes, not all findings
- ✅ **Historical context:** SARIF upload tracks findings over time
- ✅ **Actionable:** Developers can fix issues before merge

### Example Output

```markdown
# 🔍 Security Diff Report

**Baseline:** `main` (2025-11-05, balanced profile)
**Current:** `feature/new-api` (2025-11-05, balanced profile)

---

## 📊 Summary

| Metric | Count | Change |
|--------|-------|--------|
| **New Findings** | 3 | 🔴 +3 |
| **Resolved Findings** | 1 | ✅ -1 |
| **Modified Findings** | 0 | ➖ 0 |
| **Net Change** | +2 | 🔴 Worsening |

### New Findings by Severity
- 🔴 **HIGH**: 1
- 🟡 **MEDIUM**: 2

---

## ⚠️ New Findings (3)

### 🔴 HIGH (1)

<details>
<summary><b>SQL Injection in user query handler</b></summary>

**Rule:** `semgrep.sql-injection`
**File:** `src/api/users.py:127`
**Tool:** semgrep v1.50.0

**Message:**
Unsanitized user input flows into SQL query. Use parameterized queries.

**Remediation:**
```python
# BAD
query = f"SELECT * FROM users WHERE id = {user_id}"

# GOOD
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))
```

</details>
```

---

## Use Case 2: CI/CD Security Gate

**Goal:** Block pull request merges if new CRITICAL or HIGH findings are introduced.

### Workflow

```bash
# Generate diff report
jmo diff baseline-results/ current-results/ --format json --output diff.json

# Extract new CRITICAL/HIGH count
NEW_COUNT=$(jq '.statistics.new_by_severity.CRITICAL + .statistics.new_by_severity.HIGH' diff.json)

# Fail if any found
if [ "$NEW_COUNT" -gt 0 ]; then
  echo "❌ Security gate failed: $NEW_COUNT new CRITICAL/HIGH findings"
  exit 1
fi
```

### Configuration Options

**Strict mode:** Block on CRITICAL only

```bash
NEW_CRITICAL=$(jq '.statistics.new_by_severity.CRITICAL // 0' diff.json)
if [ "$NEW_CRITICAL" -gt 0 ]; then
  exit 1
fi
```

**Moderate mode:** Block on CRITICAL/HIGH

```bash
NEW_COUNT=$(jq '(.statistics.new_by_severity.CRITICAL // 0) + (.statistics.new_by_severity.HIGH // 0)' diff.json)
if [ "$NEW_COUNT" -gt 0 ]; then
  exit 1
fi
```

**Relaxed mode:** Block only if net change is negative

```bash
NET_CHANGE=$(jq '.statistics.net_change' diff.json)
if [ "$NET_CHANGE" -gt 5 ]; then  # More than 5 new findings overall
  exit 1
fi
```

### Benefits

- ✅ **Enforce standards:** No high-risk code reaches main
- ✅ **Clear feedback:** Developers know exactly what to fix
- ✅ **Customizable:** Adjust thresholds per team/project
- ✅ **Non-blocking option:** Run informational mode with `allow_failure: true`

---

## Use Case 3: Sprint Tracking

**Goal:** Track security improvements over a sprint to measure remediation progress.

### Workflow

**At Sprint Start:**

```bash
# Scan and save baseline
jmo scan --repo . --profile balanced --results-dir sprint-start/
```

**At Sprint End:**

```bash
# Scan current state
jmo scan --repo . --profile balanced --results-dir sprint-end/

# Generate diff
jmo diff sprint-start/ sprint-end/ \
  --format html \
  --output sprint-report.html

# Generate JSON for metrics
jmo diff sprint-start/ sprint-end/ \
  --format json \
  --output sprint-metrics.json
```

### Metrics to Track

```bash
# Extract sprint metrics
RESOLVED=$(jq '.statistics.total_resolved' sprint-metrics.json)
NEW=$(jq '.statistics.total_new' sprint-metrics.json)
NET=$(jq '.statistics.net_change' sprint-metrics.json)
TREND=$(jq -r '.statistics.trend' sprint-metrics.json)

echo "📊 Sprint Security Metrics:"
echo "  - Issues resolved: $RESOLVED"
echo "  - New issues: $NEW"
echo "  - Net improvement: $NET"
echo "  - Trend: $TREND"
```

### Benefits

- ✅ **Visualize progress:** See security improvements over time
- ✅ **Celebrate wins:** Highlight resolved findings
- ✅ **Identify trends:** Detect if security is improving or degrading
- ✅ **Team motivation:** Gamify security remediation

---

## Use Case 4: Release Validation

**Goal:** Ensure releases have fewer security issues than previous versions.

### Workflow

```bash
# Scan previous release (from tag)
git checkout v1.0.0
jmo scan --repo . --profile deep --results-dir v1.0.0-results/

# Scan release candidate
git checkout v1.1.0-rc1
jmo scan --repo . --profile deep --results-dir v1.1.0-results/

# Generate diff
jmo diff v1.0.0-results/ v1.1.0-results/ \
  --format md \
  --output release-diff.md

# Gate: Ensure no new CRITICAL/HIGH
NEW_HIGH=$(jq '(.statistics.new_by_severity.CRITICAL // 0) + (.statistics.new_by_severity.HIGH // 0)' release-diff.json)
if [ "$NEW_HIGH" -gt 0 ]; then
  echo "❌ Release blocked: $NEW_HIGH new CRITICAL/HIGH findings"
  exit 1
fi
```

### Pre-Release Checklist

- [ ] No new CRITICAL findings
- [ ] No new HIGH findings (or document exceptions)
- [ ] Net change is negative (more resolved than new)
- [ ] Trend is "improving" or "stable"
- [ ] All SARIF uploaded to Code Scanning
- [ ] Release notes include security improvements

### Benefits

- ✅ **Quality gate:** Prevent security regressions in releases
- ✅ **Audit trail:** Document security posture per release
- ✅ **Customer confidence:** Show security improvements in release notes

---

## Use Case 5: Historical Trend Analysis

**Goal:** Analyze security posture changes over multiple scans using SQLite storage.

### Workflow

```bash
# Store scans in SQLite (automatic after every scan)
jmo scan --repo . --profile balanced --results-dir results/
# Scan auto-stored to ~/.jmo/scans.db

# List historical scans
jmo history list --last 10

# Compare two historical scans
jmo diff --scan abc123 --scan def456 --format json

# Generate trend analysis (requires SQLite storage)
jmo trends --last 10 --format html --output trends.html
```

### Long-Term Metrics

```bash
# Query historical data
sqlite3 ~/.jmo/scans.db <<EOF
SELECT
  timestamp_iso,
  total_findings,
  severity_counts
FROM scans
ORDER BY timestamp DESC
LIMIT 10;
EOF
```

### Benefits

- ✅ **Historical context:** See security posture evolution
- ✅ **Trend detection:** Identify long-term improvements/regressions
- ✅ **Executive reporting:** Generate monthly/quarterly reports
- ✅ **Compliance:** Maintain audit trail of security scans

---

## Advanced Workflows

### Multi-Repository Comparison

Compare security posture across multiple repositories:

```bash
#!/bin/bash
# scan-all-repos.sh

REPOS=("frontend" "backend" "mobile-app")

for repo in "${REPOS[@]}"; do
  echo "📊 Scanning $repo..."
  cd "$repo"
  jmo scan --repo . --profile fast --results-dir "../scans/$repo"
  cd ..
done

# Generate cross-repo comparison
# (Custom script to aggregate findings)
```

### Dependency Update Validation

Validate security impact of dependency updates:

```bash
# Before update
jmo scan --repo . --profile balanced --results-dir pre-update/

# Update dependencies
npm update
# or: pip install --upgrade -r requirements.txt

# After update
jmo scan --repo . --profile balanced --results-dir post-update/

# Check impact
jmo diff pre-update/ post-update/ \
  --format md \
  --output dependency-update-impact.md
```

### Security Regression Testing

Integrate into automated test suites:

```python
# pytest fixture for security diff
import pytest
import subprocess
import json

@pytest.fixture(scope="session")
def security_baseline():
    """Run baseline security scan once per test session."""
    subprocess.run([
        "jmo", "scan",
        "--repo", ".",
        "--profile", "fast",
        "--results-dir", "test-baseline/"
    ], check=True)

def test_no_new_critical_findings(security_baseline):
    """Ensure no new CRITICAL findings introduced."""
    # Scan current code
    subprocess.run([
        "jmo", "scan",
        "--repo", ".",
        "--profile", "fast",
        "--results-dir", "test-current/"
    ], check=True)

    # Generate diff
    subprocess.run([
        "jmo", "diff",
        "test-baseline/", "test-current/",
        "--format", "json",
        "--output", "test-diff.json"
    ], check=True)

    # Load diff
    with open("test-diff.json") as f:
        diff = json.load(f)

    # Assert no new CRITICAL
    new_critical = diff["statistics"]["new_by_severity"].get("CRITICAL", 0)
    assert new_critical == 0, f"Found {new_critical} new CRITICAL findings"
```

---

## Troubleshooting

### Issue: Diff shows all findings as "new"

**Cause:** Fingerprint IDs changed between scans (e.g., different tool versions)

**Solution:**

```bash
# Ensure same tool versions
jmo scan --repo . --profile fast --tools trivy,semgrep --results-dir baseline/
jmo scan --repo . --profile fast --tools trivy,semgrep --results-dir current/

# Verify fingerprint stability
jq '.id' baseline/summaries/findings.json | head -5
jq '.id' current/summaries/findings.json | head -5
```

### Issue: PR comment too large (>65k characters)

**Cause:** Too many findings in diff report

**Solution:**

```bash
# Filter to CRITICAL/HIGH only
jmo diff baseline/ current/ \
  --format md \
  --output pr-diff.md \
  --severity CRITICAL,HIGH

# Or show only new findings
jmo diff baseline/ current/ \
  --format md \
  --output pr-diff.md \
  --only new
```

### Issue: Modification detection shows false positives

**Cause:** Tool vendors updated severity ratings or CWE mappings

**Solution:**

```bash
# Disable modification detection
jmo diff baseline/ current/ \
  --no-modifications \
  --format md \
  --output pr-diff.md

# Or filter specific modification types
jmo diff baseline/ current/ \
  --modification-types severity,priority \
  --format md \
  --output pr-diff.md
```

### Issue: SARIF upload fails in GitHub Actions

**Cause:** Missing `security-events: write` permission

**Solution:**

```yaml
permissions:
  contents: read
  security-events: write  # Required for SARIF upload
```

### Issue: Diff performance is slow (>5s)

**Cause:** Large result directories with many findings

**Solution:**

```bash
# Use --no-modifications for faster diffs
jmo diff baseline/ current/ \
  --no-modifications \
  --format json \
  --output diff.json

# Or use SQLite mode (faster for repeated queries)
jmo diff --scan abc123 --scan def456 --format json
```

---

## Best Practices

1. **Use consistent profiles:** Always compare scans with the same profile (fast/balanced/deep)
2. **Version control baselines:** Commit baseline results for reproducible comparisons
3. **Automate everything:** Use CI/CD for consistent, automated diffing
4. **Filter intelligently:** Use `--severity` and `--tool` filters to reduce noise
5. **Document exceptions:** If blocking on findings, document why specific findings are acceptable
6. **Monitor trends:** Track security posture over time, not just point-in-time
7. **Educate developers:** Share diff reports and celebrate security improvements
8. **Iterate on thresholds:** Start strict, relax based on team feedback

---

## Additional Resources

- [GitHub Actions Example](github-actions-diff.yml)
- [GitLab CI Example](gitlab-ci-diff.yml)
- [USER_GUIDE.md - Diff Command Reference](../USER_GUIDE.md#jmo-diff)
- [DIFF_IMPLEMENTATION_PLAN.md](../../dev-only/1.0.0/DIFF_IMPLEMENTATION_PLAN.md)

---

**Last Updated:** 2025-11-05
**Version:** 1.0.0
