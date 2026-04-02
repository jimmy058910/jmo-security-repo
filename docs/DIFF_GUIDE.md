# Machine-Readable Diffs Guide

**Compare two security scans to identify new, resolved, and modified findings.**

The `jmo diff` command enables intelligent comparison of scan results using fingerprint-based matching, supporting PR reviews, CI/CD gates, remediation tracking, and trend analysis.

---

## Table of Contents

- [Key Features](#key-features)
- [Two Comparison Modes](#two-comparison-modes)
  - [Directory Mode (Primary)](#1-directory-mode-primary)
  - [SQLite Mode (Historical)](#2-sqlite-mode-historical)
- [CLI Reference](#cli-reference)
- [Output Formats](#output-formats)
  - [JSON (Machine-Readable)](#json-machine-readable)
  - [Markdown (PR Comments)](#markdown-pr-comments)
  - [HTML (Interactive Dashboard)](#html-interactive-dashboard)
  - [SARIF 2.1.0 (Code Scanning)](#sarif-210-code-scanning)
- [Modification Detection](#modification-detection)
- [CI/CD Integration Examples](#cicd-integration-examples)
  - [GitHub Actions (PR Comments)](#github-actions-pr-comments)
  - [GitLab CI (Merge Request Comments)](#gitlab-ci-merge-request-comments)
- [Common Workflows](#common-workflows)
- [Performance](#performance)
- [Troubleshooting](#troubleshooting)
- [Related Documentation](#related-documentation)

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Fingerprint Matching** | O(n) performance with stable finding IDs |
| **Four Classifications** | NEW, RESOLVED, UNCHANGED, MODIFIED |
| **Modification Detection** | Tracks severity upgrades, compliance changes, priority shifts |
| **Four Output Formats** | JSON, Markdown (PR comments), HTML (interactive), SARIF 2.1.0 |
| **Flexible Filtering** | By severity, tool, category, or combination |
| **CI/CD Ready** | GitHub Actions and GitLab CI examples included |

---

## Two Comparison Modes

### 1. Directory Mode (Primary)

Compare findings from two results directories:

```bash
# Basic comparison
jmo diff baseline-results/ current-results/ --format md --output pr-diff.md

# With filtering
jmo diff baseline/ current/ \
  --format json \
  --severity CRITICAL,HIGH \
  --only new \
  --output critical-findings.json
```

**Use Cases:**

- PR reviews: Compare main branch vs feature branch
- Release validation: Compare previous release vs current
- Sprint tracking: Compare sprint start vs sprint end

### 2. SQLite Mode (Historical)

Compare two scan IDs from history database:

```bash
# Compare historical scans
jmo diff \
  --scan abc123-baseline \
  --scan def456-current \
  --format md \
  --output diff.md

# Custom database location
jmo diff \
  --scan scan-id-1 \
  --scan scan-id-2 \
  --db /custom/path/history.db \
  --format json
```

**Use Cases:**

- Long-term trend analysis
- Quarterly compliance reporting
- Regression detection across releases

---

## CLI Reference

```bash
jmo diff [OPTIONS] [BASELINE] [CURRENT]
```

### Positional Arguments (Directory Mode)

| Argument | Description |
|----------|-------------|
| `BASELINE` | Baseline results directory |
| `CURRENT` | Current results directory |

### SQLite Mode Options

| Option | Description |
|--------|-------------|
| `--scan SCAN_ID` | Scan ID (provide twice: baseline, current) |
| `--db PATH` | History database path (default: `.jmo/history.db`) |

### Output Options

| Option | Description |
|--------|-------------|
| `--output PATH` | Output file path (extension added by format) |
| `--format FORMAT` | `json`, `md`, `html`, `sarif` (can specify multiple) |

### Filtering Options

| Option | Description |
|--------|-------------|
| `--severity SEV [SEV...]` | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| `--tool TOOL [TOOL...]` | Filter by tool names |
| `--only CATEGORY` | `new`, `resolved`, `modified` |
| `--no-modifications` | Skip modification detection (faster) |

### Behavior Options

| Option | Description |
|--------|-------------|
| `--fail-on SEV` | Exit 1 if new findings at severity level |
| `--quiet` | Suppress summary output |

---

## Output Formats

### JSON (Machine-Readable)

Schema with metadata wrapper:

```json
{
  "meta": {
    "diff_version": "1.0.0",
    "jmo_version": "1.0.0",
    "timestamp": "2025-11-05T10:30:00Z",
    "baseline": {},
    "current": {}
  },
  "statistics": {
    "total_new": 12,
    "total_resolved": 20,
    "total_unchanged": 120,
    "total_modified": 2,
    "net_change": -8,
    "trend": "improving",
    "new_by_severity": {},
    "resolved_by_severity": {}
  },
  "findings": {
    "new": [],
    "resolved": [],
    "modified": []
  }
}
```

**Use Case:** CI/CD automation, programmatic analysis

---

### Markdown (PR Comments)

Human-readable format with collapsible details:

```markdown
# Security Diff Report

## Summary

| Metric | Count | Change |
|--------|-------|--------|
| **New Findings** | 12 | +12 |
| **Resolved Findings** | 20 | -20 |
| **Net Change** | -8 | Improving |

## New Findings (12)

### CRITICAL (1)

<details>
<summary><b>SQL Injection in user query handler</b></summary>

**Rule:** `semgrep.sql-injection`
**File:** `src/database.py:127`

**Message:** Unsanitized user input flows into SQL query...

</details>
```

**Use Case:** GitHub/GitLab PR comments, team reviews

---

### HTML (Interactive Dashboard)

Self-contained interactive dashboard with:

- Severity filtering
- Search/filter by rule, tool, path
- Side-by-side comparison for modified findings
- Collapsible finding cards
- Dark mode support

**Use Case:** Visual exploration, management reporting

---

### SARIF 2.1.0 (Code Scanning)

GitHub/GitLab Code Scanning integration with `baselineState` annotations:

```json
{
  "runs": [{
    "results": [{
      "baselineState": "new",
      "properties": {
        "diff_category": "new",
        "baseline_severity": null,
        "current_severity": "error"
      }
    }]
  }]
}
```

**Use Case:** GitHub Security tab, GitLab SAST dashboard

---

## Modification Detection

**Enabled by default** - detects 5 types of changes:

| Change Type | Description |
|-------------|-------------|
| **Severity Changes** | MEDIUM -> HIGH (upgrade/downgrade) |
| **Priority Changes** | EPSS/KEV updates (risk delta) |
| **Compliance Changes** | New framework mappings added |
| **CWE Changes** | CWE classification updates |
| **Message Changes** | Finding description updates |

**Example:**

```json
{
  "fingerprint": "abc123...",
  "changes": {
    "severity": ["MEDIUM", "HIGH"],
    "priority": [45.2, 78.9],
    "compliance_frameworks": [
      ["owasp"],
      ["owasp", "pci_dss"]
    ]
  }
}
```

**Disable for performance:**

```bash
jmo diff baseline/ current/ --no-modifications  # 30% faster
```

---

## CI/CD Integration Examples

### GitHub Actions (PR Comments)

```yaml
name: Security Diff on PR

on:
  pull_request:
    branches: [main]

jobs:
  security-diff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      # Scan baseline (main branch)
      - name: Checkout main
        run: git checkout main

      - name: Scan main branch
        run: jmo scan --repo . --profile balanced --results-dir baseline-results

      # Scan current PR
      - name: Checkout PR
        run: git checkout ${{ github.event.pull_request.head.sha }}

      - name: Scan PR branch
        run: jmo scan --repo . --profile balanced --results-dir current-results

      # Generate diff
      - name: Generate diff
        run: |
          jmo diff baseline-results/ current-results/ \
            --format md \
            --output pr-diff.md \
            --fail-on HIGH

      # Post PR comment
      - name: Post PR comment
        if: always()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const diff = fs.readFileSync('pr-diff.md', 'utf8');

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: diff
            });
```

**Complete example:** [docs/examples/github-actions-diff.yml](examples/github-actions-diff.yml)

---

### GitLab CI (Merge Request Comments)

```yaml
security-diff:
  stage: test
  script:
    # Scan baseline
    - git checkout $CI_MERGE_REQUEST_TARGET_BRANCH_NAME
    - jmo scan --repo . --profile balanced --results-dir baseline/

    # Scan current
    - git checkout $CI_COMMIT_SHA
    - jmo scan --repo . --profile balanced --results-dir current/

    # Generate diff
    - jmo diff baseline/ current/ --format md --output diff.md

    # Post MR comment via GitLab API
    - |
      curl --request POST \
        --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
        --data-urlencode "body@diff.md" \
        "$CI_API_V4_URL/projects/$CI_PROJECT_ID/merge_requests/$CI_MERGE_REQUEST_IID/notes"
  only:
    - merge_requests
```

**Complete example:** [docs/examples/gitlab-ci-diff.yml](examples/gitlab-ci-diff.yml)

---

## Common Workflows

### 1. PR Review (Show Only New Issues)

```bash
# Compare branches
jmo diff baseline/ current/ --format md --only new --severity HIGH,CRITICAL

# CI gate: Block if new HIGH/CRITICAL
jmo diff baseline/ current/ --format json --output diff.json
NEW_COUNT=$(jq '(.statistics.new_by_severity.CRITICAL // 0) + (.statistics.new_by_severity.HIGH // 0)' diff.json)
[ "$NEW_COUNT" -eq 0 ] || exit 1
```

### 2. Sprint Remediation Tracking

```bash
# Track fixes between sprint start and end
jmo diff \
  --scan sprint-start-abc123 \
  --scan sprint-end-def456 \
  --format json \
  --output sprint-kpis.json

# Extract remediation stats
jq '.statistics.resolved_by_severity' sprint-kpis.json
```

### 3. Release Validation

```bash
# Compare previous release vs current
jmo diff \
  --scan v0.9.0-scan-id \
  --scan v1.0.0-scan-id \
  --format html \
  --output release-validation.html

# Fail if regression (more new than resolved)
NET=$(jq '.statistics.net_change' diff.json)
[ "$NET" -le 0 ] || exit 1
```

### 4. Compliance Regression Detection

```bash
# Check if PR introduces new OWASP Top 10 findings
jmo diff baseline/ current/ --format json --only new --output diff.json
jq '[.findings.new[] | select(.compliance.owaspTop10_2021 != null)]' diff.json

# Fail if any OWASP findings
COUNT=$(jq '[.findings.new[] | select(.compliance.owaspTop10_2021 != null)] | length' diff.json)
[ "$COUNT" -eq 0 ] || exit 1
```

---

## Performance

**Targets:**

| Metric | Target |
|--------|--------|
| 1,000 findings diff | <500ms |
| 10,000 findings diff | <2s |
| Complexity | O(n) fingerprint set operations |

**Optimization Tips:**

- Use `--no-modifications` for faster diffs (30% speedup)
- Filter early: `--severity HIGH,CRITICAL` reduces processing
- SQLite mode is slightly faster (indexed queries)

---

## Troubleshooting

### "Baseline directory not found"

- Ensure `baseline-results/` exists and contains `summaries/findings.json`
- Run `jmo scan` to generate baseline first

### "Scan ID not found in database"

- List available scans: `jmo history list`
- Check database path: `--db .jmo/history.db`

### "No findings in diff output"

- Check filtering: Remove `--severity` or `--only` flags
- Verify scans actually differ: `diff baseline/summaries/findings.json current/summaries/findings.json`

### "Modified findings not detected"

- Ensure `--no-modifications` not set
- Modification detection requires same fingerprint with different metadata

### "Diff taking too long"

- Use `--no-modifications` for 30% speedup
- Filter by severity: `--severity CRITICAL,HIGH`
- Check scan sizes: `wc -l baseline/summaries/findings.json`

---

## Related Documentation

- [Trend Analysis Guide](TRENDS_GUIDE.md) - Statistical trend analysis over time
- [Historical Storage Guide](HISTORY_GUIDE.md) - Database storage for scan results
- [Results Guide](RESULTS_GUIDE.md) - Understanding scan output formats
- [CI/CD Integration](USER_GUIDE.md#cicd-pipeline-integration-strategy) - CI/CD integration help
- [Diff Workflows Examples](examples/diff-workflows.md) - Complete workflow examples
- [User Guide](USER_GUIDE.md) - Complete reference documentation
