# JMo Security Results Guide

**The Complete Guide to Understanding, Triaging, and Acting on Your Security Scan Results**

## Table of Contents

1. [Quick Start: Understanding Your Results](#quick-start-understanding-your-results)
2. [The Results Directory Structure](#the-results-directory-structure)
3. [Reading the Summary Report](#reading-the-summary-report)
4. [Understanding Compliance Reports](#understanding-compliance-reports)
5. [Triage Workflow: What to Fix First](#triage-workflow-what-to-fix-first)
6. [Working with Findings Data](#working-with-findings-data)
7. [Using the Interactive Dashboard](#using-the-interactive-dashboard)
8. [Suppressing False Positives](#suppressing-false-positives)
9. [Integrating with Your Workflow](#integrating-with-your-workflow)
10. [Advanced: SARIF and CI/CD Integration](#advanced-sarif-and-cicd-integration)

---

## Quick Start: Understanding Your Results

After running a JMo Security scan, you'll get multiple output formats. Here's where to start:

### 1. Start with the Summary (30 seconds)

```bash
cat results/summaries/SUMMARY.md
```

**What you'll see:**
- Total findings count with severity breakdown (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- Top files with the most findings
- Which tools found what
- Quick remediation priorities

**Example:**
```
Total findings: 8058 | 🔴 3 CRITICAL | 🔴 91 HIGH | 🟡 280 MEDIUM | ⚪ 7391 LOW
```

**What this means:** Most findings are LOW severity (common for code quality checks). Focus on the 3 CRITICAL and 91 HIGH first.

### 2. Open the Interactive Dashboard (2 minutes)

```bash
# Linux/WSL
xdg-open results/summaries/dashboard.html

# macOS
open results/summaries/dashboard.html

# Windows
start results/summaries/dashboard.html
```

**What you'll see:**
- Visual charts showing severity distribution
- Filterable table of all findings
- Direct links to affected files
- Compliance framework mappings

**Pro Tip:** Use the dashboard's search/filter to focus on specific file paths, rule IDs, or severities.

### 3. Check Compliance Requirements (1 minute)

```bash
cat results/summaries/COMPLIANCE_SUMMARY.md
```

**What you'll see:**
- Which OWASP Top 10 categories are affected
- CWE Top 25 coverage
- NIST CSF, PCI DSS, CIS Controls, MITRE ATT&CK mappings

**Example:**
```
OWASP Top 10 2021: 4/10 categories
- A02:2021 (Cryptographic Failures): 102 findings
- A03:2021 (Injection): 301 findings
```

**What this means:** If you need SOC 2, PCI DSS, or ISO 27001 compliance, these reports show exactly which security findings map to which requirements.

---

## The Results Directory Structure

After a scan, you'll have this directory structure:

```
results/
├── individual-repos/          # Raw tool outputs per repository
│   └── <repo-name>/
│       ├── trivy.json
│       ├── semgrep.json
│       ├── trufflehog.json
│       └── ...
├── individual-images/         # Raw outputs per container image (v0.6.0+)
│   └── <image-name>/
│       ├── trivy.json
│       └── syft.json
├── individual-iac/            # Raw outputs per IaC file (v0.6.0+)
│   └── <file-name>/
│       └── checkov.json
├── individual-web/            # Raw outputs per web URL (v0.6.0+)
│   └── <domain>/
│       ├── zap.json
│       └── nuclei.json
├── individual-gitlab/         # Raw outputs per GitLab repo (v0.6.0+)
│   └── <group>_<repo>/
│       └── trufflehog.json
├── individual-k8s/            # Raw outputs per K8s cluster (v0.6.0+)
│   └── <context>_<namespace>/
│       └── trivy.json
└── summaries/                 # Aggregated, normalized outputs
    ├── findings.json          # All findings in CommonFinding schema
    ├── findings.yaml          # YAML format (optional)
    ├── findings.sarif         # SARIF 2.1.0 for CI/CD integration
    ├── SUMMARY.md             # Human-readable summary
    ├── COMPLIANCE_SUMMARY.md  # Multi-framework compliance report
    ├── PCI_DSS_COMPLIANCE.md  # Detailed PCI DSS report
    ├── attack-navigator.json  # MITRE ATT&CK Navigator visualization
    ├── dashboard.html         # Interactive web dashboard
    └── timings.json           # Performance profiling (if --profile used)
```

### Which Files to Use When

| Task | File to Use | Why |
|------|-------------|-----|
| **Quick overview** | `SUMMARY.md` | Human-readable, shows priorities |
| **Deep investigation** | `dashboard.html` | Interactive filtering, clickable links |
| **Compliance audit** | `COMPLIANCE_SUMMARY.md`, `PCI_DSS_COMPLIANCE.md` | Framework-specific reports |
| **CI/CD integration** | `findings.sarif` | Standard format for GitHub/GitLab/Azure DevOps |
| **Custom scripting** | `findings.json` | Machine-readable, stable schema |
| **Threat modeling** | `attack-navigator.json` | Import into MITRE ATT&CK Navigator |
| **Tool-specific deep dive** | `individual-*/tool.json` | Original tool output (before normalization) |

---

## Reading the Summary Report

The `SUMMARY.md` file is your starting point for triage. Here's how to read it:

### Section 1: Headline Stats

```markdown
Total findings: 8058 | 🔴 3 CRITICAL | 🔴 91 HIGH | 🟡 280 MEDIUM | ⚪ 7391 LOW
```

**What to look for:**
- **CRITICAL/HIGH count** - Your immediate priority
- **Total vs. actionable** - If you have 8000 findings but only 94 are HIGH+, most are noise or low-priority code quality issues

### Section 2: Top Risks by File

```markdown
| File | Findings | Severity | Top Issue |
|------|----------|----------|-----------|
| tests/e2e/fixtures/iac/aws-s3-public.tf | 19 | 🔴 CRITICAL | RDS Cluster backup retention <1 day |
| Dockerfile.alpine | 6 | 🔴 CRITICAL | ':latest' tag used |
```

**What to do:**
1. **Check if it's production code** - Test fixtures, examples, archived code can often be suppressed
2. **Assess real-world impact** - "RDS backup retention" is critical for production, not for a demo repo
3. **Prioritize by exposure** - Public-facing code (web apps, APIs) > internal tools > test code

### Section 3: By Tool

```markdown
- **trivy**: 81 findings (🔴 3 CRITICAL, 🔴 28 HIGH)
- **semgrep**: 32 findings (🔴 6 HIGH, 🟡 24 MEDIUM)
- **trufflehog**: 7 findings (🟡 7 MEDIUM)
```

**What this tells you:**
- **Trivy found CRITICAL** - Likely container or dependency vulnerabilities (CVEs)
- **Semgrep found HIGH** - Code security issues (SQL injection, XSS, command injection)
- **TruffleHog found MEDIUM** - Potential secrets (unverified by default)

**Tool-Specific Context:**
- **TruffleHog MEDIUM = unverified secrets** - May be false positives (test keys, examples)
- **Trivy CRITICAL = CVE** - Likely real vulnerability with CVSS ≥9.0
- **Bandit LOW = assert statements** - Code quality, not security risk

### Section 4: Remediation Priorities

```markdown
1. **Fix Image user should not be 'root'** (5 findings) → Review container security
2. **Address 63 code security issues** → Review SAST findings
```

**How to use this:**
- Start with **systemic issues** (same fix applies to multiple findings)
- Example: "User should not be root" in 5 Dockerfiles → One fix (add `USER jmo` to base Dockerfile template)

### Section 5: By Category

```markdown
- 🔧 Code Quality: 7673 findings (95% of total)
- 🛡️ Vulnerabilities: 79 findings (1% of total)
- 🔑 Secrets: 9 findings (0% of total)
```

**What this means:**
- **95% Code Quality** - Bandit flagging `assert` statements, missing type hints, etc. (LOW priority)
- **1% Vulnerabilities** - CVEs in dependencies (CRITICAL/HIGH priority)
- **0% Secrets** - Good! But verify the 9 findings aren't real credentials

---

## Understanding Compliance Reports

JMo Security auto-enriches findings with 6 compliance frameworks. Here's how to use each:

### 1. OWASP Top 10 2021

**File:** `COMPLIANCE_SUMMARY.md` → OWASP section

**Example:**
```markdown
| Category | Findings |
|----------|----------|
| A02:2021 | 102 |
| A03:2021 | 301 |
```

**What it means:**
- **A02:2021 - Cryptographic Failures:** 102 findings related to weak crypto, missing encryption, insecure storage
- **A03:2021 - Injection:** 301 findings related to SQL/command/code injection

**When to use:**
- **Web app security audits** - OWASP is the standard for web application risks
- **Developer training** - Show devs which OWASP categories they're triggering
- **Compliance:** Required for PCI DSS 6.2.4, SOC 2

### 2. CWE Top 25 2024

**File:** `COMPLIANCE_SUMMARY.md` → CWE section

**Example:**
```markdown
| CWE ID | Rank | Findings |
|--------|------|----------|
| CWE-798 | 18 | 7 |
```

**What it means:**
- **CWE-798 (Rank 18):** Use of Hard-coded Credentials - 7 findings
- **Rank:** Position in MITRE's "Most Dangerous Software Weaknesses" list (1 = worst)

**When to use:**
- **CVE remediation** - CWEs are referenced in CVE descriptions
- **Secure coding standards** - Map your findings to industry-recognized weakness categories
- **Vendor assessments** - Customers often ask "Do you scan for CWE Top 25?"

### 3. NIST Cybersecurity Framework 2.0

**File:** `COMPLIANCE_SUMMARY.md` → NIST CSF section

**Example:**
```markdown
| Function | Findings |
|----------|----------|
| GOVERN   | 374 |
| IDENTIFY | 8047 |
| PROTECT  | 22 |
| DETECT   | 7673 |
```

**What it means:**
- **GOVERN:** Findings related to policies, risk management, supply chain (CWE-798, dependency issues)
- **IDENTIFY:** Asset management, vulnerability discovery (most SBOM findings)
- **PROTECT:** Access control, secure configuration (Dockerfile USER, file permissions)
- **DETECT:** Monitoring, logging, threat detection (code quality checks)

**When to use:**
- **Enterprise risk management** - Map security findings to business risk functions
- **Compliance:** Required for NIST 800-53, FISMA, some government contracts
- **Executive reporting** - CISOs understand NIST CSF better than CWE IDs

### 4. PCI DSS 4.0

**File:** `PCI_DSS_COMPLIANCE.md` (dedicated report)

**Example:**
```markdown
### Requirement 6.2.4: Bespoke software is developed securely
**Priority:** CRITICAL
**Findings:** 7673
```

**What it means:**
- **Requirement 6.2.4:** All custom code must be scanned for vulnerabilities
- **7673 findings:** Includes code quality (many LOW), but also HIGH findings like SQL injection

**When to use:**
- **Payment processing apps** - Required if you handle credit cards
- **Compliance audits** - Auditors want evidence of secure development
- **Merchant onboarding** - Payment processors require PCI DSS evidence

**Pro Tip:** Filter by HIGH/CRITICAL only for audit reports. Auditors care about exploitable vulnerabilities, not `assert` statements.

### 5. CIS Controls v8.1

**File:** `COMPLIANCE_SUMMARY.md` → CIS section

**Example:**
```markdown
| Framework | Coverage |
|-----------|----------|
| CIS Controls v8.1 | 14 controls |
```

**What it means:**
- **14 controls triggered** - Your findings map to 14 of the 18 CIS Critical Security Controls
- **Implementation Groups (IG1/IG2/IG3):** IG1 = basic cyber hygiene, IG3 = advanced controls

**When to use:**
- **Cyber insurance** - Insurers often require CIS Controls compliance
- **Benchmarking** - Compare your posture against CIS benchmarks
- **Prioritization** - Focus on IG1 controls first (foundational)

### 6. MITRE ATT&CK

**Files:**
- `COMPLIANCE_SUMMARY.md` → MITRE ATT&CK section
- `attack-navigator.json` → Import into [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

**Example:**
```markdown
**Top 5 Techniques:**
1. **T1195** - Supply Chain Compromise (374 findings)
2. **T1552** - Unsecured Credentials (7 findings)
```

**What it means:**
- **T1195 - Supply Chain Compromise:** Findings in dependencies, SBOM packages (Syft detected 374 packages)
- **T1552 - Unsecured Credentials:** Hardcoded secrets, weak crypto

**When to use:**
- **Threat modeling** - Map findings to attacker tactics (Initial Access, Persistence, etc.)
- **Purple team exercises** - Focus defensive controls on detected techniques
- **SOC analysis** - Help SOC analysts understand attack paths

**How to visualize:**
1. Open [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
2. Upload `attack-navigator.json`
3. See heatmap of which techniques your findings map to

---

## Triage Workflow: What to Fix First

You've got 8000 findings. Here's how to prioritize them in 30 minutes:

### Step 1: Filter by Severity (5 minutes)

```bash
# Extract only CRITICAL and HIGH findings
jq '[.[] | select(.severity == "CRITICAL" or .severity == "HIGH")]' \
  results/summaries/findings.json > critical-high.json

# Count them
jq 'length' critical-high.json
# Output: 94
```

**Result:** You now have 94 findings to review instead of 8058.

### Step 2: Categorize by Location (10 minutes)

```bash
# Group by file path pattern
jq 'group_by(.location.path | split("/")[0:3] | join("/"))' critical-high.json > grouped.json
```

**Categories to look for:**
1. **Production code** (`src/`, `scripts/`, root files)
2. **Test code** (`tests/`, `fixtures/`, `samples/`)
3. **Dependencies** (`.venv/`, `node_modules/`, `vendor/`)
4. **CI/CD** (`.github/`, `Dockerfile`, `docker-compose.yml`)

**Triage decision tree:**

```
Is it in production code?
  YES → Priority 1 (fix immediately)
  NO → Is it in dependencies?
    YES → Priority 3 (check if exploitable in production)
    NO → Is it a test fixture?
      YES → Priority 4 (suppress or document as intentional)
      NO → Priority 2 (CI/CD hardening)
```

### Step 3: Check for False Positives (10 minutes)

**Common false positives:**

| Tool | Rule | False Positive Pattern | How to Verify |
|------|------|------------------------|---------------|
| Bandit | B101 | `assert` statements in test files | Check file path contains `tests/` or `test_` |
| Bandit | B411 | XML parsing in PyPI packages | Check path is `.venv/lib/python3.X/site-packages/` |
| Semgrep | `run-shell-injection` | GitHub Actions `${{ github.* }}` in echo statements | Check it's not used in script execution |
| TruffleHog | Generic secrets | Example credentials in docs/README | Check for comments like `# Example (not real)` |
| Trivy | CVEs in test dependencies | Vulnerable packages only imported in tests | Check if imported in production code |

**Example: Bandit B101 in test files**

```bash
# Find all B101 findings in test files
jq '.[] | select(.ruleId == "B101" and (.location.path | contains("test")))' \
  critical-high.json | jq -s 'length'
# Output: 62
```

**Decision:** Suppress B101 for test files (pytest uses `assert` extensively)

### Step 4: Identify Systemic Issues (5 minutes)

**What to look for:**

```bash
# Top 5 most common rules
jq '[.[] | .ruleId] | group_by(.) | map({rule: .[0], count: length}) | sort_by(.count) | reverse | .[0:5]' \
  critical-high.json
```

**Example output:**
```json
[
  {"rule": "B101", "count": 62},
  {"rule": "CVE-2023-12345", "count": 15},
  {"rule": "root-user", "count": 5}
]
```

**What this means:**
1. **B101 (62 occurrences)** - Systemic pattern (likely test files) → One suppression rule fixes all 62
2. **CVE-2023-12345 (15 occurrences)** - Same vulnerable dependency in 15 places → One `pip install --upgrade` fixes all 15
3. **root-user (5 occurrences)** - 5 Dockerfiles missing `USER` statement → One template fix

**Time savings:** Fixing 3 root causes eliminates 82 findings (87% of HIGH findings).

---

## Working with Findings Data

All findings follow the **CommonFinding schema v1.2.0**. Here's how to query them:

### Schema Overview

```json
{
  "schemaVersion": "1.2.0",
  "id": "ca88e028c8a99735",               // Unique fingerprint
  "ruleId": "DL3018",                      // Tool-specific rule ID
  "severity": "MEDIUM",                    // CRITICAL/HIGH/MEDIUM/LOW/INFO
  "title": "Pin versions in apk add",
  "message": "Instead of `apk add <package>` use `apk add <package>=<version>`",
  "tool": {
    "name": "hadolint",
    "version": "2.12.0"
  },
  "location": {
    "path": "/home/user/repo/Dockerfile.alpine",
    "startLine": 14,
    "endLine": 14
  },
  "compliance": {
    "owaspTop10_2021": ["A05:2021"],
    "cweTop25_2024": [{"id": "CWE-1104", "rank": 23}],
    "cisControlsV8_1": [{"control": "4.1", "implementationGroup": "IG1"}],
    "nistCsf2_0": [{"function": "PROTECT", "category": "PR.IP", "subcategory": "PR.IP-1"}],
    "pciDss4_0": [{"requirement": "2.2.1", "priority": "HIGH"}],
    "mitreAttack": [{"tactic": "Initial Access", "technique": "T1190"}]
  }
}
```

### Common Queries

#### 1. Find All Secrets

```bash
jq '[.[] | select(.tags[]? == "secret" or .ruleId | contains("secret"))]' \
  results/summaries/findings.json > secrets.json
```

#### 2. Find Exploitable CVEs (CVSS ≥7.0)

```bash
jq '[.[] | select(.cvss? and (.cvss.score >= 7.0))]' \
  results/summaries/findings.json > exploitable-cves.json
```

#### 3. Find All SQL Injection Issues

```bash
jq '[.[] | select(.ruleId | contains("sql") or (.message | ascii_downcase | contains("sql injection")))]' \
  results/summaries/findings.json > sql-injection.json
```

#### 4. Get OWASP A03 (Injection) Findings

```bash
jq '[.[] | select(.compliance.owaspTop10_2021[]? == "A03:2021")]' \
  results/summaries/findings.json > owasp-a03.json
```

#### 5. Find Findings in Production Code Only

```bash
jq '[.[] | select(.location.path | contains("tests/") | not)
           | select(.location.path | contains(".venv/") | not)
           | select(.location.path | contains("fixtures/") | not)]' \
  results/summaries/findings.json > production-only.json
```

#### 6. Group Findings by File

```bash
jq 'group_by(.location.path)
    | map({path: .[0].location.path, count: length, severities: [.[] | .severity] | unique})
    | sort_by(.count) | reverse' \
  results/summaries/findings.json > by-file.json
```

---

## Using the Interactive Dashboard

The HTML dashboard is the fastest way to explore findings visually.

### Features

1. **Severity Charts**
   - Pie chart: Distribution by severity
   - Bar chart: Findings per tool
   - Trend chart: If you run scans over time

2. **Filterable Table**
   - Click column headers to sort
   - Use search box to filter by file path, rule ID, message
   - Click severity badges to filter by severity

3. **Direct Links**
   - Click file paths to open in your editor (if configured)
   - Click rule IDs to see documentation (if tool supports it)

4. **Compliance Tabs**
   - Switch between OWASP, CWE, NIST, PCI DSS views
   - See which findings map to which requirements

### Tips for Effective Use

**1. Start with Severity Filter**
- Click the "HIGH" severity badge to see only high-priority findings
- Review each finding's remediation field for fix guidance

**2. Use Path Filters to Focus**
- Search for `src/` to see only production code
- Search for `Dockerfile` to see container issues
- Search for `.tf` to see IaC findings

**3. Export Filtered Results**
- After filtering, use browser's "Save Page As" to save filtered view
- Or copy filtered table data to Excel/Sheets for team review

**4. Share with Non-Technical Stakeholders**
- Dashboard is self-contained (no external dependencies)
- Can be emailed or uploaded to internal wiki
- Works offline

---

## Suppressing False Positives

Once you've identified false positives, suppress them to reduce noise in future scans.

### Method 1: Create `jmo.suppress.yml`

Create `jmo.suppress.yml` in your repo root:

```yaml
suppressions:
  # Suppress by fingerprint ID (most specific)
  - id: "ca88e028c8a99735"
    reason: "Accepted risk: Using alpine:latest for faster builds"

  # Suppress by rule + path pattern
  - ruleId: "B101"
    path: "tests/*"
    reason: "pytest uses assert statements extensively"

  # Suppress by path only (all findings in directory)
  - path: ".venv/*"
    reason: "Third-party dependencies vetted by PyPI"

  # Suppress by rule + line number (very specific)
  - ruleId: "run-shell-injection"
    path: ".github/workflows/ci.yml"
    line: 74
    reason: "Read-only echo of commit message in CI logs"
```

### Method 2: Update Scan Configuration

Edit `jmo.yml`:

```yaml
# Exclude entire directories from scanning
exclude_paths:
  - ".venv/"
  - ".venv-*/"
  - "node_modules/"
  - "tests/e2e/fixtures/"

# Per-tool configuration
per_tool:
  bandit:
    flags:
      - "--exclude"
      - ".venv,.venv-pypi,.post-release-venv"
      - "--skip"
      - "B101,B404"  # Skip assert and import-related checks

  semgrep:
    flags:
      - "--exclude"
      - "tests/e2e/fixtures/"
      - "--exclude"
      - "docs/archive/"
```

### Method 3: Tool-Specific Configuration

Some tools have their own config files:

**Bandit** (`.bandit`):
```yaml
exclude_dirs:
  - .venv
  - tests/fixtures
  - samples/

skips:
  - B101  # assert_used
  - B404  # import_subprocess
```

**Semgrep** (`.semgrepignore`):
```
.venv/
tests/e2e/fixtures/
docs/archive/
```

### Viewing Suppressed Findings

After adding suppressions, re-run the scan:

```bash
jmotools balanced --repos-dir .
cat results/summaries/SUPPRESSIONS.md
```

**Example output:**
```markdown
# Suppression Summary

**Total Suppressions:** 1,245

## By Reason
- Third-party dependencies vetted by PyPI: 1,180
- Test fixtures with intentional vulnerabilities: 62
- Accepted risk: alpine:latest for faster builds: 3
```

---

## Integrating with Your Workflow

### Scenario 1: Pre-Commit Hooks

**Goal:** Catch HIGH/CRITICAL issues before committing

**Setup:**

1. Add to `.pre-commit-config.yaml`:

```yaml
- repo: local
  hooks:
    - id: jmo-security-scan
      name: JMo Security Scan (Fast Profile)
      entry: bash -c 'jmotools fast --repos-dir . && [ $(jq "[.[] | select(.severity == \"HIGH\" or .severity == \"CRITICAL\")] | length" results/summaries/findings.json) -eq 0 ]'
      language: system
      pass_filenames: false
      always_run: true
```

2. Install: `pre-commit install`

**Result:** Commits are blocked if HIGH/CRITICAL findings exist.

### Scenario 2: CI/CD Pipeline (GitHub Actions)

**Goal:** Gate deployments on security scan results

**Setup:**

Add to `.github/workflows/security-scan.yml`:

```yaml
name: Security Scan

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run JMo Security Scan
        run: |
          docker run --rm -v "$(pwd):/scan" jmo-security:latest \
            scan --repo /scan --profile-name balanced --human-logs

      - name: Check for HIGH/CRITICAL findings
        run: |
          HIGH_COUNT=$(jq '[.[] | select(.severity == "HIGH" or .severity == "CRITICAL")] | length' \
            results/summaries/findings.json)

          if [ "$HIGH_COUNT" -gt 0 ]; then
            echo "❌ Found $HIGH_COUNT HIGH/CRITICAL findings"
            cat results/summaries/SUMMARY.md
            exit 1
          fi

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results/summaries/findings.sarif

      - name: Archive Results
        uses: actions/upload-artifact@v4
        with:
          name: security-scan-results
          path: results/summaries/
```

**Result:** PRs are blocked if HIGH/CRITICAL findings exist, and results appear in GitHub Security tab.

### Scenario 3: Weekly Scheduled Scans

**Goal:** Track security posture over time

**Setup:**

Add to `.github/workflows/weekly-scan.yml`:

```yaml
name: Weekly Security Audit

on:
  schedule:
    - cron: '0 10 * * 1'  # Every Monday at 10 AM UTC
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Deep Scan
        run: |
          docker run --rm -v "$(pwd):/scan" jmo-security:latest \
            scan --repo /scan --profile-name deep --human-logs --profile

      - name: Generate Trend Report
        run: |
          # Compare to last week's results
          CURRENT_HIGH=$(jq '[.[] | select(.severity == "HIGH")] | length' results/summaries/findings.json)
          PREVIOUS_HIGH=$(curl -s "https://api.github.com/repos/${{ github.repository }}/actions/artifacts" \
            | jq '.artifacts[] | select(.name == "weekly-scan-results") | .id' | head -1)

          echo "## Security Trend Report" >> $GITHUB_STEP_SUMMARY
          echo "**Current HIGH findings:** $CURRENT_HIGH" >> $GITHUB_STEP_SUMMARY
          echo "**Change from last week:** ..." >> $GITHUB_STEP_SUMMARY

      - name: Upload Results
        uses: actions/upload-artifact@v4
        with:
          name: weekly-scan-results
          path: results/summaries/
          retention-days: 90
```

**Result:** Weekly audit with historical tracking.

### Scenario 4: Slack/Email Notifications

**Goal:** Alert team when new HIGH findings appear

**Setup:**

```yaml
- name: Send Slack Alert
  if: failure()
  uses: slackapi/slack-github-action@v1
  with:
    webhook-url: ${{ secrets.SLACK_WEBHOOK }}
    payload: |
      {
        "text": "⚠️ Security Scan Failed",
        "blocks": [
          {
            "type": "section",
            "text": {
              "type": "mrkdwn",
              "text": "*Security scan found HIGH/CRITICAL findings*\n\nView results: ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"
            }
          }
        ]
      }
```

---

## Advanced: SARIF and CI/CD Integration

### What is SARIF?

**SARIF (Static Analysis Results Interchange Format)** is an industry-standard JSON format for security findings, supported by:
- GitHub Code Scanning
- GitLab SAST
- Azure DevOps
- SonarQube
- Visual Studio Code

JMo Security outputs `findings.sarif` (SARIF 2.1.0) for seamless integration.

### GitHub Code Scanning Integration

**Upload findings to GitHub Security tab:**

```yaml
- name: Upload SARIF to GitHub
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results/summaries/findings.sarif
    category: jmo-security-scan
```

**What you get:**
- Findings appear in **Security → Code scanning** tab
- Pull requests show findings as annotations
- Auto-dismiss findings when fixed
- Track trends over time

**Required permissions:**

```yaml
permissions:
  security-events: write  # Required for SARIF upload
  contents: read
```

### GitLab SAST Integration

**Upload to GitLab Security Dashboard:**

```yaml
security-scan:
  stage: test
  script:
    - docker run --rm -v "$(pwd):/scan" jmo-security:latest scan --repo /scan
    - cp results/summaries/findings.sarif gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

**Result:** Findings appear in GitLab Security Dashboard and Merge Request widget.

### Azure DevOps Integration

**Upload to Azure DevOps Security tab:**

```yaml
- task: PublishBuildArtifacts@1
  inputs:
    pathtoPublish: 'results/summaries/findings.sarif'
    artifactName: 'CodeAnalysisLogs'
    publishLocation: 'Container'
```

---

## Real-World Triage Examples

### Example 1: You Have 8058 Findings (Like Our Sample)

**Initial Reaction:** Overwhelming! Where do I start?

**Triage Process:**

1. **Check the breakdown:**
   - 3 CRITICAL
   - 91 HIGH
   - 280 MEDIUM
   - 7,391 LOW
   - 293 INFO

2. **Focus on CRITICAL (3 findings):**
   - 2 in test fixtures (`tests/e2e/fixtures/iac/aws-s3-public.tf`)
   - 1 in sample code (`samples/fixtures/infra-demo/`)
   - **Decision:** Suppress (not production code)

3. **Triage HIGH (91 findings):**
   - 83 in `.venv/` (third-party dependencies)
   - 6 in `tests/e2e/fixtures/` (intentional vulnerabilities)
   - 2 in `.github/workflows/` (false positive: echo statements)
   - **Decision:** Suppress all 91 (see `dev-only/triage-high-findings.md`)

4. **Result:**
   - **0 findings in production code requiring fixes**
   - 15 minutes to triage
   - 5 minutes to add suppressions

**Lesson:** Most findings in large scans are noise. Use systematic triage to find the signal.

### Example 2: You Have 50 CRITICAL Findings

**Initial Reaction:** Panic! Are we insecure?

**Triage Process:**

1. **Group by tool:**
   - Trivy: 40 CRITICAL (CVEs in dependencies)
   - Checkov: 10 CRITICAL (IaC misconfigurations)

2. **Investigate Trivy CVEs:**
   ```bash
   jq '[.[] | select(.tool.name == "trivy" and .severity == "CRITICAL")]' findings.json
   ```

   **Example finding:**
   ```json
   {
     "ruleId": "CVE-2023-12345",
     "message": "SQL injection in package XYZ <1.2.3",
     "cvss": {"score": 9.8},
     "remediation": "Upgrade to XYZ >=1.2.4"
   }
   ```

3. **Check if exploitable:**
   - Is the vulnerable function actually used in our code?
   - Use `grep -r "vulnerable_function" src/` to check

4. **Fix strategy:**
   - **Immediate:** Upgrade dependencies with known exploits
   - **Short-term:** Add suppressions for unused vulnerable code paths
   - **Long-term:** Remove unused dependencies

5. **Result:**
   - 40 CVEs → 8 actually exploitable
   - Fixed with 2 `pip install --upgrade` commands
   - Took 1 hour

**Lesson:** Not all CRITICAL findings are equally critical. Context matters.

---

## Compliance Audit Checklist

### Preparing for a SOC 2 Audit

**Auditor will ask:** "How do you ensure secure development?"

**Your answer:** "We scan all code with JMo Security. Here's our report:"

1. **Provide SUMMARY.md** - Show total findings and triage process
2. **Provide COMPLIANCE_SUMMARY.md** - Map findings to NIST CSF
3. **Provide SUPPRESSIONS.md** - Show false positives are documented
4. **Provide scan schedule** - Show evidence of weekly/monthly scans

**Pro Tip:** Create a "SOC 2 Evidence" folder:
```bash
mkdir -p compliance/soc2/
cp results/summaries/SUMMARY.md compliance/soc2/scan-$(date +%Y-%m-%d).md
cp results/summaries/COMPLIANCE_SUMMARY.md compliance/soc2/
```

### Preparing for a PCI DSS Audit

**Auditor will ask:** "Do you scan custom code for vulnerabilities? (Requirement 6.2.4)"

**Your answer:** "Yes. See attached PCI DSS compliance report:"

1. **Provide PCI_DSS_COMPLIANCE.md**
2. **Filter to show only production code:**
   ```bash
   jq '[.[] | select(.location.path | contains("tests/") | not)]' findings.json > production-findings.json
   ```
3. **Document remediation:**
   - HIGH findings fixed within 30 days
   - MEDIUM findings fixed within 90 days

**Pro Tip:** Use `--fail-on HIGH` in CI to prevent merging code with HIGH findings:
```bash
jmotools ci --repo . --fail-on HIGH
```

---

## Troubleshooting Common Issues

### Issue 1: "Too many LOW findings - can't find real issues"

**Solution:** Filter aggressively

```bash
# Create a "findings-priority.json" with only actionable items
jq '[.[] | select(.severity == "CRITICAL" or .severity == "HIGH")
         | select(.location.path | contains("tests/") | not)
         | select(.location.path | contains(".venv/") | not)]' \
  findings.json > findings-priority.json
```

### Issue 2: "Same CVE appears in 50 different locations"

**Solution:** Group by ruleId to see systemic issues

```bash
jq 'group_by(.ruleId) | map({rule: .[0].ruleId, count: length, severity: .[0].severity})
    | sort_by(.count) | reverse' findings.json
```

**Example output:**
```json
[
  {"rule": "CVE-2023-12345", "count": 50, "severity": "HIGH"}
]
```

**Fix:** One `pip install --upgrade vulnerable-package` fixes all 50.

### Issue 3: "Dashboard won't open / shows blank page"

**Cause:** Browser security restrictions on local HTML files with embedded JavaScript

**Solution:**
1. **Use a local web server:**
   ```bash
   cd results/summaries
   python3 -m http.server 8000
   # Open http://localhost:8000/dashboard.html
   ```

2. **Or use `file://` with Chrome flag:**
   ```bash
   google-chrome --allow-file-access-from-files dashboard.html
   ```

### Issue 4: "Compliance report shows 0 mappings"

**Cause:** Using an old version of JMo Security (pre-v0.5.1)

**Solution:** Upgrade to v0.6.2+:
```bash
pip install --upgrade jmo-security-audit
```

Compliance auto-enrichment was added in v0.5.1.

---

## Quick Reference

### Essential Commands

```bash
# View summary
cat results/summaries/SUMMARY.md

# Count HIGH/CRITICAL findings
jq '[.[] | select(.severity == "HIGH" or .severity == "CRITICAL")] | length' results/summaries/findings.json

# Find secrets
jq '[.[] | select(.tags[]? == "secret")]' results/summaries/findings.json

# Group by file
jq 'group_by(.location.path) | map({file: .[0].location.path, count: length})' results/summaries/findings.json

# Get OWASP A03 findings
jq '[.[] | select(.compliance.owaspTop10_2021[]? == "A03:2021")]' results/summaries/findings.json

# Filter production code only
jq '[.[] | select(.location.path | contains("tests/") or contains(".venv/") | not)]' results/summaries/findings.json
```

### File Quick Reference

| File | What It Is | When to Use |
|------|------------|-------------|
| `SUMMARY.md` | Human-readable overview | First stop for triage |
| `dashboard.html` | Interactive web UI | Deep investigation |
| `findings.json` | Machine-readable findings | Scripting, custom analysis |
| `findings.sarif` | SARIF 2.1.0 format | CI/CD, GitHub/GitLab integration |
| `COMPLIANCE_SUMMARY.md` | Multi-framework report | Compliance audits |
| `PCI_DSS_COMPLIANCE.md` | PCI DSS-specific report | Payment compliance |
| `attack-navigator.json` | MITRE ATT&CK heatmap | Threat modeling |

---

## Next Steps

1. **Start with SUMMARY.md** - Get the big picture
2. **Open dashboard.html** - Explore interactively
3. **Triage HIGH/CRITICAL** - Focus on production code
4. **Suppress false positives** - Create `jmo.suppress.yml`
5. **Integrate with CI/CD** - Add to GitHub Actions
6. **Track trends** - Run weekly scans

**Questions?**
- [GitHub Discussions](https://github.com/jimmy058910/jmo-security-repo/discussions)
- [Documentation](https://github.com/jimmy058910/jmo-security-repo/docs)
- [Open an Issue](https://github.com/jimmy058910/jmo-security-repo/issues)

---

*Generated by JMo Security content-generator skill | Last updated: 2025-10-23*
