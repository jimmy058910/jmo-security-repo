# Trend Analysis Guide

**Analyze security scan trends over time using statistical methods, detect regressions, and track developer remediation efforts.**

---

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [CLI Commands](#cli-commands)
  - [jmo trends analyze](#jmo-trends-analyze)
  - [jmo trends show](#jmo-trends-show)
  - [jmo trends regressions](#jmo-trends-regressions)
  - [jmo trends score](#jmo-trends-score)
  - [jmo trends compare](#jmo-trends-compare)
  - [jmo trends insights](#jmo-trends-insights)
  - [jmo trends explain](#jmo-trends-explain)
  - [jmo trends developers](#jmo-trends-developers)
- [Export Formats](#export-formats)
  - [CSV Export](#csv-export)
  - [Prometheus Export](#prometheus-export)
  - [Grafana Dashboard JSON Export](#grafana-dashboard-json-export)
  - [Dashboard JSON Export](#dashboard-json-export)
- [Wizard Integration](#wizard-integration)
- [CI/CD Integration](#cicd-integration)
  - [GitHub Actions Example](#github-actions-example)
  - [GitLab CI Example](#gitlab-ci-example)
- [Docker Usage](#docker-usage)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)
- [Statistical Methods Reference](#statistical-methods-reference)
  - [Mann-Kendall Trend Test](#mann-kendall-trend-test)
- [Future Enhancements](#future-enhancements)
- [Related Documentation](#related-documentation)

---

## Overview

The Trend Analysis feature provides powerful tools to understand how your security posture evolves over time. Built on the [Historical Storage](HISTORY_GUIDE.md) foundation, it uses the Mann-Kendall statistical test and other advanced analytics to identify meaningful trends, detect regressions, and measure security improvements.

### Key Features

| Feature | Description |
|---------|-------------|
| **Statistical Trend Detection** | Mann-Kendall test (p < 0.05) for statistically significant trends |
| **Regression Detection** | Identify new CRITICAL/HIGH findings between scans |
| **Security Score** | Quantify security posture (0-100 scale) with letter grades (A-F) |
| **Automated Insights** | AI-powered recommendations based on trend patterns |
| **Developer Attribution** | Track who fixed what using git blame integration |
| **Multiple Export Formats** | CSV, Prometheus, Grafana, Dashboard JSON |
| **Rich Output Formats** | Terminal tables, JSON, interactive HTML reports |

### What Makes It Unique

Unlike simple diff tools, Trend Analysis uses rigorous statistical methods to distinguish real trends from noise. The Mann-Kendall test ensures trends are statistically significant (p < 0.05), not just random fluctuations.

---

## Quick Start

### Prerequisites

Trend analysis requires at least 2 scans stored in history database:

```bash
# First scan (baseline)
jmo scan --repo ./myapp --profile balanced --store-history

# Make changes, then run second scan
jmo scan --repo ./myapp --profile balanced --store-history

# Analyze trends
jmo trends analyze
```

### Basic Workflow

```bash
# 1. Run initial baseline scan
jmo scan --repo ./myapp --profile balanced --store-history

# 2. Run periodic scans (daily/weekly)
jmo scan --repo ./myapp --profile balanced --store-history

# 3. View trend analysis
jmo trends analyze

# 4. Check for regressions
jmo trends regressions

# 5. View security score
jmo trends score
```

---

## CLI Commands

### jmo trends analyze

**Perform comprehensive trend analysis across stored scans.**

```bash
jmo trends analyze [OPTIONS]
```

#### Options

| Option | Description |
|--------|-------------|
| `--branch NAME` | Filter scans by Git branch (default: all branches) |
| `--since TIMESTAMP` | Analyze scans since timestamp (Unix epoch or ISO 8601) |
| `--scans N` | Analyze last N scans (default: all scans) |
| `--min-scans N` | Minimum scans required for analysis (default: 2) |
| `--format FORMAT` | Output format: `terminal` (default), `json`, `html` |
| `--output FILE` | Write output to file instead of stdout |
| `--db PATH` | Database path (default: `.jmo/history.db`) |
| `--export FORMAT` | Export data: `csv`, `prometheus`, `grafana`, `dashboard` |
| `--export-file FILE` | Export file path (required with `--export`) |

#### Examples

```bash
# Basic analysis (all scans, all branches)
jmo trends analyze

# Analyze last 10 scans on main branch
jmo trends analyze --branch main --scans 10

# Analyze scans from last 30 days
jmo trends analyze --since "30 days ago"

# Generate HTML report
jmo trends analyze --format html --output trend-report.html

# Export to Prometheus metrics
jmo trends analyze --export prometheus --export-file metrics.prom

# Export to Grafana JSON dashboard
jmo trends analyze --export grafana --export-file dashboard.json
```

#### Sample Terminal Output

```text
+====================================================================+
|                     Trend Analysis Report                          |
+====================================================================+

Analysis Period: 2025-10-01 to 2025-11-05 (35 days)
Scans Analyzed: 12
Branch: main
Profile: balanced

--------------------------------------------------------------------
Severity Trends (Mann-Kendall Test, alpha=0.05)
--------------------------------------------------------------------

  Severity    Trend        Tau      p-value   Significance
  -------------------------------------------------------------------
  CRITICAL    improving   -0.682    0.001     * significant
  HIGH        stable      -0.242    0.123       not significant
  MEDIUM      improving   -0.515    0.012     * significant
  LOW         stable       0.091    0.587       not significant
  INFO        stable      -0.030    0.861       not significant

--------------------------------------------------------------------
Top Rules (Last 30 Days)
--------------------------------------------------------------------

  Rule ID              Severity    Count    % of Total
  -------------------------------------------------------------------
  CVE-2024-1234        CRITICAL       18        14.5%
  CWE-89               HIGH           12         9.7%
  CWE-79               HIGH           10         8.1%
  CVE-2024-5678        HIGH            8         6.5%

--------------------------------------------------------------------
Security Score
--------------------------------------------------------------------

  Current Score: 78 (C)
  Previous Score: 65 (D)
  Change: +13 points (improving)

  Grade Distribution:
    A (90-100):  2 scans
    B (80-89):   1 scan
    C (70-79):   4 scans
    D (60-69):   3 scans
    F (<60):     2 scans

--------------------------------------------------------------------
Automated Insights
--------------------------------------------------------------------

  [OK] CRITICAL findings decreasing (-68% over 12 scans)
  [OK] Security score improving (+20% in last 30 days)
  [!]  HIGH findings still elevated (>10 per scan)
  [!]  3 regressions detected in last scan (scan_abc123)
  [i]  Most common issue: CVE-2024-1234 (upgrade dependency X to v2.0+)
```

---

### jmo trends show

**Show scan context window (N scans before/after a specific scan).**

```bash
jmo trends show [SCAN_ID] [OPTIONS]
```

#### Arguments

| Argument | Description |
|----------|-------------|
| `SCAN_ID` | Full or partial UUID (optional, defaults to latest scan) |

#### Options

| Option | Description |
|--------|-------------|
| `--window N` | Number of scans before/after to show (default: 5) |
| `--branch NAME` | Filter scans by branch |
| `--format FORMAT` | Output format: `terminal` (default), `json` |
| `--db PATH` | Database path (default: `.jmo/history.db`) |

#### Examples

```bash
# Show context for latest scan (5 before, 5 after)
jmo trends show

# Show context for specific scan
jmo trends show abc123 --window 3

# Show last 10 scans on main branch
jmo trends show --branch main --window 10
```

---

### jmo trends regressions

**Detect regressions (new CRITICAL/HIGH findings) between scans.**

```bash
jmo trends regressions [OPTIONS]
```

#### Options

| Option | Description |
|--------|-------------|
| `--scan-id ID` | Compare specific scan to previous (default: latest scan) |
| `--branch NAME` | Filter by branch |
| `--severity LEVEL` | Show regressions for severity level (default: CRITICAL,HIGH) |
| `--format FORMAT` | Output format: `terminal` (default), `json` |
| `--db PATH` | Database path (default: `.jmo/history.db`) |

#### Examples

```bash
# Detect regressions in latest scan
jmo trends regressions

# Check specific scan for regressions
jmo trends regressions --scan-id abc123

# Show CRITICAL regressions only
jmo trends regressions --severity CRITICAL

# Check regressions on staging branch
jmo trends regressions --branch staging
```

---

### jmo trends score

**Calculate and display security score (0-100) with letter grades.**

```bash
jmo trends score [OPTIONS]
```

#### Options

| Option | Description |
|--------|-------------|
| `--branch NAME` | Filter by branch |
| `--scans N` | Show last N scans (default: all) |
| `--format FORMAT` | Output format: `terminal` (default), `json` |
| `--db PATH` | Database path (default: `.jmo/history.db`) |

#### Score Calculation

```text
Score = 100 - (critical_count * 10) - (high_count * 3) - (medium_count * 1)
Score = max(0, Score)  # Floor at 0

Grades:
  A: 90-100
  B: 80-89
  C: 70-79
  D: 60-69
  F: <60
```

#### Examples

```bash
# Show current security score
jmo trends score

# Show score history for last 10 scans
jmo trends score --scans 10

# Score for specific branch
jmo trends score --branch main
```

---

### jmo trends compare

**Side-by-side comparison of two scans.**

```bash
jmo trends compare SCAN_ID_1 SCAN_ID_2 [OPTIONS]
```

#### Arguments

| Argument | Description |
|----------|-------------|
| `SCAN_ID_1` | First scan ID (full or partial UUID) |
| `SCAN_ID_2` | Second scan ID (full or partial UUID) |

#### Options

| Option | Description |
|--------|-------------|
| `--format FORMAT` | Output format: `terminal` (default), `json` |
| `--db PATH` | Database path (default: `.jmo/history.db`) |

#### Examples

```bash
# Compare two specific scans
jmo trends compare abc123 def456

# Compare latest scan with previous
jmo trends compare latest previous
```

---

### jmo trends insights

**Generate automated insights and recommendations based on trends.**

```bash
jmo trends insights [OPTIONS]
```

#### Options

| Option | Description |
|--------|-------------|
| `--branch NAME` | Filter by branch |
| `--scans N` | Analyze last N scans (default: all) |
| `--format FORMAT` | Output format: `terminal` (default), `json` |
| `--db PATH` | Database path (default: `.jmo/history.db`) |

#### Examples

```bash
# Generate insights for all scans
jmo trends insights

# Insights for last 10 scans on main
jmo trends insights --branch main --scans 10
```

---

### jmo trends explain

**Explain trend terminology and statistical methods.**

```bash
jmo trends explain [TOPIC]
```

#### Available Topics

| Topic | Description |
|-------|-------------|
| `mann-kendall` | Mann-Kendall statistical test |
| `security-score` | Security score calculation |
| `regression` | Regression detection logic |
| `trends` | Trend classification (improving/stable/degrading) |
| `all` | Show all explanations |

#### Examples

```bash
# Explain Mann-Kendall test
jmo trends explain mann-kendall

# Explain security score formula
jmo trends explain security-score

# Show all explanations
jmo trends explain all
```

---

### jmo trends developers

**Track developer remediation efforts using git blame attribution.**

```bash
jmo trends developers [OPTIONS]
```

#### Options

| Option | Description |
|--------|-------------|
| `--scan-id ID` | Analyze specific scan (default: latest) |
| `--branch NAME` | Filter by branch |
| `--format FORMAT` | Output format: `terminal` (default), `json` |
| `--team-map FILE` | JSON file mapping developers to teams |
| `--velocity` | Show developer velocity metrics |
| `--db PATH` | Database path (default: `.jmo/history.db`) |

#### Examples

```bash
# Show developer attribution for latest scan
jmo trends developers

# Show attribution with team aggregation
jmo trends developers --team-map teams.json

# Show developer velocity (fixes per week)
jmo trends developers --velocity

# Analyze specific scan
jmo trends developers --scan-id abc123
```

#### Team Mapping File

Create a `teams.json` file:

```json
{
  "Frontend Team": ["alice@example.com", "bob@example.com"],
  "Backend Team": ["charlie@example.com", "dave@example.com"],
  "DevOps Team": ["eve@example.com"]
}
```

---

## Export Formats

Trend analysis supports 4 export formats for integration with external systems.

### CSV Export

**Use case:** Excel, Google Sheets, data analysis

```bash
jmo trends analyze --export csv --export-file trends.csv
```

**CSV Structure:**

```csv
scan_id,timestamp,branch,profile,critical,high,medium,low,info,total,score,grade
abc123,2025-11-05T14:30:15,main,balanced,2,10,20,30,5,67,78,C
def456,2025-11-04T08:45:33,main,balanced,3,12,22,32,8,77,65,D
```

---

### Prometheus Export

**Use case:** Monitoring, alerting, Grafana dashboards

```bash
jmo trends analyze --export prometheus --export-file metrics.prom
```

**Prometheus Metrics Format:**

```prometheus
# HELP jmo_scan_findings_total Total findings by severity
# TYPE jmo_scan_findings_total gauge
jmo_scan_findings_total{severity="critical",branch="main",profile="balanced"} 2
jmo_scan_findings_total{severity="high",branch="main",profile="balanced"} 10
jmo_scan_findings_total{severity="medium",branch="main",profile="balanced"} 20

# HELP jmo_security_score Security posture score (0-100)
# TYPE jmo_security_score gauge
jmo_security_score{branch="main",profile="balanced"} 78

# HELP jmo_scan_duration_seconds Scan duration in seconds
# TYPE jmo_scan_duration_seconds gauge
jmo_scan_duration_seconds{branch="main",profile="balanced"} 245.2
```

**Grafana Query Examples:**

```promql
# Show CRITICAL findings over time
jmo_scan_findings_total{severity="critical"}

# Calculate change rate
rate(jmo_scan_findings_total{severity="high"}[7d])

# Security score trend
jmo_security_score{branch="main"}

# Alert on regressions
increase(jmo_scan_findings_total{severity="critical"}[1h]) > 0
```

---

### Grafana Dashboard JSON Export

**Use case:** Pre-built Grafana dashboards

```bash
jmo trends analyze --export grafana --export-file dashboard.json
```

**Features:**

- Time-series line charts (severity trends)
- Stat panels (current score, grade)
- Bar charts (findings by tool)
- Heatmap (findings by day of week)
- Alerts configured for regressions

**Import to Grafana:**

1. Navigate to Dashboards -> Import
2. Upload `dashboard.json`
3. Configure Prometheus data source
4. Dashboard ready to use

---

### Dashboard JSON Export

**Use case:** Custom web dashboards, React apps

```bash
jmo trends analyze --export dashboard --export-file dashboard.json
```

**JSON Structure:**

```json
{
  "summary": {
    "scan_count": 12,
    "date_range": ["2025-10-01", "2025-11-05"],
    "branch": "main",
    "profile": "balanced"
  },
  "current_scan": {
    "scan_id": "abc123",
    "timestamp": "2025-11-05T14:30:15",
    "critical": 2,
    "high": 10,
    "medium": 20,
    "low": 30,
    "info": 5,
    "total": 67,
    "score": 78,
    "grade": "C"
  },
  "trends": {
    "critical": {"trend": "improving", "tau": -0.682, "p_value": 0.001},
    "high": {"trend": "stable", "tau": -0.242, "p_value": 0.123}
  },
  "timeline": [
    {"date": "2025-11-01", "critical": 3, "high": 12, "score": 65},
    {"date": "2025-11-05", "critical": 2, "high": 10, "score": 78}
  ],
  "regressions": {
    "new_findings": 3,
    "remediated_findings": 4,
    "details": []
  },
  "top_rules": [
    {"rule_id": "CVE-2024-1234", "count": 18, "severity": "CRITICAL"}
  ]
}
```

---

## Wizard Integration

The interactive wizard includes trend analysis prompts after scans:

```text
+====================================================================+
|                   Scan Complete!                                   |
+====================================================================+

Results: ./results/summaries/dashboard.html
Findings: 67 total (2 CRITICAL, 10 HIGH, 20 MEDIUM)

Trend Analysis Available

You have 12 scans in history. Would you like to view trend analysis?

  1) View full trend analysis
  2) Check for regressions
  3) View security score
  4) Skip

Your choice [1-4]: 1

[Launches jmo trends analyze with formatted terminal output]
```

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Security Scan with Trends

on:
  push:
    branches: [main, staging]
  schedule:
    - cron: '0 2 * * 1'  # Weekly Monday 2 AM

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Restore history database
        uses: actions/cache@v4
        with:
          path: .jmo/history.db
          key: jmo-history-${{ github.ref_name }}

      - name: Run security scan
        run: |
          jmo scan --repo . --profile balanced --store-history

      - name: Analyze trends
        run: |
          jmo trends analyze --format json --output trends.json
          jmo trends regressions
          jmo trends score

      - name: Export metrics for Grafana
        run: |
          jmo trends analyze --export prometheus --export-file metrics.prom

      - name: Check for critical regressions
        run: |
          # Fail if new CRITICAL findings detected
          if jmo trends regressions --severity CRITICAL | grep -q "new findings"; then
            echo "CRITICAL regressions detected!"
            exit 1
          fi

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: security-trends
          path: |
            trends.json
            metrics.prom
            .jmo/history.db
```

### GitLab CI Example

```yaml
security_trends:
  stage: security
  script:
    - jmo scan --repo . --profile balanced --store-history --db scans.db
    - jmo trends analyze --db scans.db --format html --output trends.html
    - jmo trends regressions --db scans.db
    - jmo trends score --db scans.db
    - jmo trends analyze --db scans.db --export grafana --export-file dashboard.json
  artifacts:
    paths:
      - scans.db
      - trends.html
      - dashboard.json
    expire_in: 90 days
  cache:
    key: history-$CI_COMMIT_REF_NAME
    paths:
      - scans.db
```

---

## Docker Usage

**Volume mounting for history persistence:**

```bash
# Create persistent history directory
mkdir -p $PWD/.jmo

# Run scan with history
docker run --rm \
  -v $PWD:/scan:ro \
  -v $PWD/.jmo:/scan/.jmo \
  jmo-security:latest \
  scan --repo /scan --profile balanced --store-history

# Analyze trends
docker run --rm \
  -v $PWD/.jmo:/scan/.jmo \
  jmo-security:latest \
  trends analyze --db /scan/.jmo/history.db
```

**Docker Compose Example:**

See [docker-compose.trends.yml](../docker-compose.trends.yml) for complete example with volume persistence and multi-stage workflows.

---

## Best Practices

| Practice | Recommendation |
|----------|----------------|
| **Regular Scanning** | Run scans at consistent intervals (daily/weekly) for reliable trend detection |
| **Minimum Scans** | Need at least 5-7 scans for statistically meaningful trends |
| **Consistent Profiles** | Use same profile (balanced vs balanced) for trend comparisons |
| **Branch Strategy** | Track trends separately per branch (main, staging, dev) |
| **CI/CD Cache** | Use GitHub Actions cache or GitLab artifacts to persist history database |
| **Export Metrics** | Push Prometheus metrics to monitoring systems for alerting |
| **Regression Gating** | Fail CI if new CRITICAL/HIGH findings detected |
| **Developer Attribution** | Run in Git repos for automatic git blame tracking |

---

## Troubleshooting

### Issue: "Insufficient scans for analysis"

- **Cause:** Less than 2 scans in history database
- **Fix:** Run at least 2 scans with `--store-history` before analyzing trends

```bash
# Solution
jmo scan --repo ./myapp --profile balanced --store-history
# ... make changes ...
jmo scan --repo ./myapp --profile balanced --store-history
jmo trends analyze
```

### Issue: "No significant trends detected"

- **Cause:** Not enough scans, or findings are genuinely stable
- **Explanation:** Mann-Kendall test requires sufficient data points (5-7+ scans) and consistent patterns to detect trends
- **Fix:** Continue running scans regularly for 2-4 weeks to establish trend patterns

### Issue: Git blame not working in Docker

- **Cause:** Git history not available in container
- **Fix:** Mount Git directory and ensure `.git` is accessible

```bash
docker run --rm \
  -v $PWD:/scan \
  -v $PWD/.git:/scan/.git:ro \
  jmo-security:latest \
  trends developers
```

### Issue: Trends show "stable" when findings clearly changed

- **Cause:** Statistical significance threshold (p < 0.05) not met
- **Explanation:** Changes may be real but not statistically significant due to high variance or small sample size
- **Fix:** Accumulate more scans (10-15+) or reduce variance by using consistent scan profiles

### Issue: Developer attribution showing "unknown"

- **Cause:** Not running in Git repository, or Git history unavailable
- **Fix:**
  - Run scans from Git repo root
  - Ensure `.git` directory exists and is accessible
  - Check Git configuration: `git config user.name` and `git config user.email`

---

## Statistical Methods Reference

### Mann-Kendall Trend Test

**What it detects:** Monotonic trends (consistent increase or decrease) in time series data

**Null Hypothesis (H0):** No trend exists (data is randomly ordered)

**Alternative Hypothesis (H1):** A trend exists (data has consistent increase or decrease)

#### Test Statistic (S)

```text
S = sum of sgn(xj - xi) for all pairs i < j

where sgn(x) = {
   1  if x > 0
   0  if x = 0
  -1  if x < 0
}
```

#### Kendall's Tau

```text
tau = S / (n(n-1)/2)

where n = number of data points
```

#### Variance (for p-value calculation)

```text
Var(S) = n(n-1)(2n+5) / 18
```

#### Z-statistic

```text
Z = {
  (S - 1) / sqrt(Var(S))    if S > 0
   0                        if S = 0
  (S + 1) / sqrt(Var(S))    if S < 0
}
```

**p-value:** Probability from standard normal distribution

#### Decision Rule

- If p < 0.05 (alpha=0.05): Reject H0, trend is significant
- If p >= 0.05: Fail to reject H0, no significant trend

#### Trend Classification

```text
if p < 0.05 and tau < -0.3: "improving" (significant decrease)
elif p < 0.05 and tau > 0.3: "degrading" (significant increase)
else: "stable" (no significant trend)
```

#### Advantages

- Non-parametric (no distribution assumptions)
- Robust to outliers
- Works with non-linear trends
- Handles missing data gracefully

#### Limitations

- Requires minimum 4-5 data points (we recommend 5-7)
- Assumes independence of observations
- Detects monotonic trends only (not cyclical patterns)

---

## Future Enhancements

| Feature | Description |
|---------|-------------|
| **Threshold Alerting** | Slack/email notifications when trends degrade |
| **Interactive Web Dashboard** | React-based time-series visualizations |
| **AI-Powered Insights** | LLM-based remediation suggestions |
| **Predictive Analytics** | Forecast future finding counts using ARIMA models |
| **Custom Metrics** | Define custom aggregations and KPIs |
| **Automated Baselines** | Auto-detect "good" baseline scans for comparison |
| **Import Historical Data** | Import scans from other security tools |

---

## Related Documentation

- [Historical Storage Guide](HISTORY_GUIDE.md) - Database storage for scan results
- [Machine-Readable Diffs Guide](DIFF_GUIDE.md) - Compare two scans
- [Results Guide](RESULTS_GUIDE.md) - Understanding scan output formats
- [CI/CD Integration](USER_GUIDE.md#cicd-pipeline-integration-strategy) - CI/CD integration help
- [User Guide](USER_GUIDE.md) - Complete reference documentation
