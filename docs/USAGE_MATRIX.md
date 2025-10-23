# JMo Security Usage Type Matrix

**Generated:** 2025-10-19
**Purpose:** Real-world usage patterns mapped to tool combinations, compliance requirements, and execution modes

## Executive Summary

This matrix provides prescriptive guidance for selecting the right tools, profiles, and compliance frameworks for different security use cases. It complements the [TESTING_MATRIX.md](.claude/TESTING_MATRIX.md) by focusing on **how users should configure JMo Security** rather than how we test it.

**Key Dimensions:**

- **12 Use Cases:** Pre-commit, PR gate, nightly audit, container release, IaC validation, web app scan, compliance audit, secret scanning, CVE monitoring, fuzzing, incident response, third-party audit
- **6 Target Types:** Repositories, Container Images, IaC Files, Web URLs, GitLab Repos, Kubernetes Clusters
- **11 Tools:** trufflehog, noseyparker, semgrep, bandit, syft, trivy, checkov, hadolint, zap, falco, afl++
- **3 Profiles:** fast (5-8 min), balanced (15-20 min), deep (30-60 min)
- **6 Compliance Frameworks:** OWASP Top 10, CWE Top 25, CIS Controls, NIST CSF, PCI DSS, MITRE ATT&CK

---

## Matrix 1: Use Case × Recommended Configuration

This matrix maps common security use cases to optimal tool configurations.

| Use Case | Target Types | Tools | Profile | Fail Threshold | Est. Duration | Primary Compliance |
|----------|--------------|-------|---------|----------------|---------------|-------------------|
| **Pre-Commit Hook** | Repositories | trufflehog, semgrep, trivy | fast | CRITICAL | 5-8 min | OWASP, CWE |
| **PR Gate (Standard)** | Repositories | trufflehog, semgrep, trivy, syft | balanced | HIGH | 10-15 min | OWASP, CWE, PCI DSS |
| **PR Gate (Strict)** | Repositories, Images | trufflehog, semgrep, trivy, syft, checkov, hadolint | balanced | MEDIUM | 15-20 min | All 6 frameworks |
| **Nightly Audit** | All 6 types | All 11 tools | deep | LOW | 30-60 min | All 6 frameworks |
| **Container Release** | Images, K8s | trivy, syft, falco | balanced | HIGH | 10-15 min | CWE, NIST CSF, PCI DSS |
| **IaC Validation** | IaC Files, Repositories | trivy, checkov, semgrep | balanced | HIGH | 10-15 min | CIS Controls, NIST CSF |
| **Web App Scan (DAST)** | URLs | zap | balanced | HIGH | 15-20 min | OWASP, PCI DSS |
| **Compliance Audit** | Repositories, IaC | trivy, checkov, semgrep, hadolint | deep | MEDIUM | 20-30 min | All 6 frameworks |
| **Secret Scanning** | Repositories, GitLab | trufflehog, noseyparker | deep | CRITICAL | 15-25 min | MITRE ATT&CK, PCI DSS |
| **CVE Monitoring** | Images, K8s, Repositories | trivy, syft | fast | HIGH | 5-10 min | CWE, NIST CSF |
| **Fuzzing Campaign** | Repositories | afl++, semgrep, bandit | deep | MEDIUM | 30-90 min | CWE, MITRE ATT&CK |
| **Incident Response** | All 6 types | trufflehog, noseyparker, trivy, zap | deep | INFO | 20-40 min | MITRE ATT&CK |

**Configuration Examples:**

### Use Case: Pre-Commit Hook

**Goal:** Fast feedback loop (< 10 min) blocking critical issues

**Command:**

```bash
jmotools fast --repo . --fail-on CRITICAL --human-logs
```

**jmo.yml Override:**

```yaml
profiles:
  pre-commit:
    tools: [trufflehog, semgrep, trivy]
    threads: 8
    timeout: 300
    fail_on: "CRITICAL"
    per_tool:
      semgrep:
        flags: ["--exclude", "node_modules", "--exclude", ".git", "--timeout", "120"]
      trivy:
        flags: ["--no-progress", "--scanners", "vuln,secret"]
```

**Expected Output:**

- `findings.json`: 0-50 findings (critical secrets, high-severity CVEs, dangerous code patterns)
- `SUMMARY.md`: Severity breakdown
- `dashboard.html`: Interactive view
- **Exit Code:** 1 if CRITICAL findings exist, 0 otherwise

---

### Use Case: PR Gate (Strict)

**Goal:** Comprehensive scanning for production PRs

**Command:**

```bash
jmo scan --repo . --image myapp:pr-123 --profile-name balanced --fail-on MEDIUM
jmo report ./results --profile
```

**jmo.yml Override:**

```yaml
profiles:
  pr-gate-strict:
    tools: [trufflehog, semgrep, syft, trivy, checkov, hadolint]
    threads: 4
    timeout: 600
    fail_on: "MEDIUM"
    per_tool:
      semgrep:
        flags: ["--exclude", "node_modules", "--exclude", ".git"]
      trivy:
        flags: ["--no-progress"]
      checkov:
        flags: ["--quiet", "--compact"]
      hadolint:
        flags: ["--no-color"]
```

**Expected Output:**

- `findings.json`: 50-200 findings (secrets, CVEs, misconfigurations, code smells)
- `COMPLIANCE_SUMMARY.md`: Multi-framework compliance report
- `findings.sarif`: Upload to GitHub Security tab
- **Exit Code:** 1 if MEDIUM+ findings exist, 0 otherwise

**GitHub Actions Integration:**

```yaml
- name: Strict PR Gate
  run: |
    jmo scan --repo . --image ${{ env.IMAGE_TAG }} --profile-name pr-gate-strict
    jmo report ./results --profile
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results/summaries/findings.sarif
```

---

### Use Case: Container Release

**Goal:** Pre-production container security validation

**Command:**

```bash
jmo scan --image myapp:v1.2.3 --k8s-context prod --profile-name balanced --fail-on HIGH
jmo report ./results --profile
```

**jmo.yml Override:**

```yaml
profiles:
  container-release:
    tools: [trivy, syft, falco]
    threads: 4
    timeout: 600
    fail_on: "HIGH"
    per_tool:
      trivy:
        flags: ["--no-progress", "--scanners", "vuln,secret,misconfig", "--severity", "HIGH,CRITICAL"]
      syft:
        flags: ["-q"]
      falco:
        timeout: 900
```

**Expected Output:**

- `findings.json`: CVEs, secrets, misconfigurations in container image
- `COMPLIANCE_SUMMARY.md`: NIST CSF, PCI DSS, CWE compliance
- `timings.json`: Performance profiling
- **Exit Code:** 1 if HIGH+ findings exist, 0 otherwise

**Compliance Focus:**

- **CWE Top 25:** CVE mappings to dangerous weaknesses
- **NIST CSF 2.0:** ID.RA (Risk Assessment), DE.CM (Continuous Monitoring)
- **PCI DSS 4.0:** Requirement 6.3 (Secure Development), 11.3 (Vulnerability Scans)

---

### Use Case: IaC Validation

**Goal:** Infrastructure-as-Code security and compliance

**Command:**

```bash
jmo scan --terraform-state infrastructure.tfstate --cloudformation template.yaml --k8s-manifest k8s/ --profile-name balanced --fail-on HIGH
jmo report ./results --profile
```

**jmo.yml Override:**

```yaml
profiles:
  iac-validation:
    tools: [trivy, checkov, semgrep]
    threads: 4
    timeout: 600
    fail_on: "HIGH"
    per_tool:
      trivy:
        flags: ["--no-progress", "--scanners", "misconfig"]
      checkov:
        flags: ["--quiet", "--framework", "terraform,cloudformation,kubernetes"]
      semgrep:
        flags: ["--config", "p/terraform", "--config", "p/kubernetes"]
```

**Expected Output:**

- `findings.json`: IaC misconfigurations (overly permissive IAM, unencrypted storage, missing network policies)
- `COMPLIANCE_SUMMARY.md`: CIS Controls, NIST CSF compliance
- `PCI_DSS_COMPLIANCE.md`: PCI DSS requirement mappings
- **Exit Code:** 1 if HIGH+ findings exist, 0 otherwise

**Compliance Focus:**

- **CIS Controls v8.1:** IG2/IG3 controls for configuration management
- **NIST CSF 2.0:** PR.DS (Data Security), PR.AC (Access Control)
- **PCI DSS 4.0:** Requirement 2.2 (Configuration Standards)

---

### Use Case: Secret Scanning (Deep)

**Goal:** Comprehensive secret discovery with dual scanners

**Command:**

```bash
jmo scan --repos-dir ~/code --gitlab-repo myorg/backend --gitlab-token $TOKEN --profile-name deep --fail-on CRITICAL
jmo report ./results --profile
```

**jmo.yml Override:**

```yaml
profiles:
  secret-scanning:
    tools: [trufflehog, noseyparker]
    threads: 2
    timeout: 1200
    retries: 1
    fail_on: "CRITICAL"
    per_tool:
      trufflehog:
        flags: ["--only-verified"]  # Only verified secrets (95% false positive reduction)
      noseyparker:
        timeout: 1800
        flags: ["--max-matches-per-file", "100"]
```

**Expected Output:**

- `findings.json`: Verified secrets (API keys, tokens, passwords, SSH keys)
- `COMPLIANCE_SUMMARY.md`: MITRE ATT&CK, PCI DSS compliance
- `attack-navigator.json`: MITRE ATT&CK Navigator layer
- **Exit Code:** 1 if CRITICAL secrets found, 0 otherwise

**Compliance Focus:**

- **MITRE ATT&CK:** T1552 (Unsecured Credentials), T1078 (Valid Accounts)
- **PCI DSS 4.0:** Requirement 8.3 (Strong Cryptography for Credentials)
- **OWASP Top 10:** A07:2021 (Identification and Authentication Failures)

---

### Use Case: Nightly Audit (Comprehensive)

**Goal:** Exhaustive security audit across all asset types

**Command:**

```bash
jmo scan \
  --repos-dir ~/code \
  --images-file production-images.txt \
  --terraform-state infrastructure.tfstate \
  --url https://api.example.com \
  --gitlab-repo myorg/backend \
  --k8s-context prod \
  --k8s-all-namespaces \
  --profile-name deep \
  --fail-on LOW
jmo report ./results --profile
```

**jmo.yml Override:**

```yaml
profiles:
  nightly-audit:
    tools: [trufflehog, noseyparker, semgrep, bandit, syft, trivy, checkov, hadolint, zap, falco, afl++]
    threads: 2
    timeout: 1800
    retries: 1
    fail_on: "LOW"
    per_tool:
      noseyparker:
        timeout: 2400
      afl++:
        timeout: 3600
        flags: ["-m", "none"]
      zap:
        flags: ["-config", "spider.maxDuration=20"]
```

**Expected Output:**

- `findings.json`: 500-2000 findings (all severities, all target types)
- `COMPLIANCE_SUMMARY.md`: All 6 frameworks
- `PCI_DSS_COMPLIANCE.md`: Detailed PCI DSS report
- `attack-navigator.json`: MITRE ATT&CK coverage heatmap
- `timings.json`: Per-tool performance profiling
- **Exit Code:** 1 if LOW+ findings exist (informational, expected to fail)

**Compliance Focus:** All 6 frameworks (exhaustive compliance coverage)

**Recommended Schedule:** Daily at 2 AM UTC (low traffic hours)

---

## Matrix 2: Target Type × Primary Tools

This matrix shows the **essential tools** for each target type (minimum viable configuration).

| Target Type | Essential Tools | Secondary Tools | Coverage Area |
|-------------|-----------------|-----------------|---------------|
| **Repositories** | trufflehog, semgrep, trivy | noseyparker, bandit, syft, checkov, hadolint, falco, afl++ | Secrets, SAST, SCA, IaC, Dockerfile, runtime, fuzzing |
| **Container Images** | trivy, syft | — | CVEs, SBOM, secrets, misconfigurations |
| **IaC Files** | trivy, checkov | semgrep | Misconfigurations, policy violations, SAST |
| **Web URLs** | zap | — | DAST, OWASP Top 10, runtime vulnerabilities |
| **GitLab Repos** | trufflehog | — | Verified secrets |
| **Kubernetes Clusters** | trivy, falco | — | Misconfigurations, runtime security, CVEs |

**Recommendation:** Use **essential tools** for fast/balanced profiles, add **secondary tools** for deep profile.

---

## Matrix 3: Compliance Framework × Use Case Priority

This matrix shows which compliance frameworks are most relevant for each use case.

| Use Case | OWASP Top 10 | CWE Top 25 | CIS Controls | NIST CSF 2.0 | PCI DSS 4.0 | MITRE ATT&CK |
|----------|--------------|------------|--------------|--------------|-------------|--------------|
| **Pre-Commit Hook** | ⭐⭐⭐ | ⭐⭐⭐ | ⭐ | ⭐ | ⭐ | ⭐ |
| **PR Gate (Standard)** | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ | ⭐⭐ | ⭐⭐ | ⭐ |
| **PR Gate (Strict)** | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| **Nightly Audit** | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **Container Release** | ⭐⭐ | ⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| **IaC Validation** | ⭐⭐ | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| **Web App Scan** | ⭐⭐⭐ | ⭐⭐ | ⭐⭐ | ⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| **Compliance Audit** | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **Secret Scanning** | ⭐⭐ | ⭐⭐ | ⭐⭐ | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **CVE Monitoring** | ⭐⭐ | ⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| **Fuzzing Campaign** | ⭐⭐ | ⭐⭐⭐ | ⭐ | ⭐⭐ | ⭐⭐ | ⭐⭐⭐ |
| **Incident Response** | ⭐⭐ | ⭐⭐ | ⭐⭐ | ⭐⭐ | ⭐⭐ | ⭐⭐⭐ |

**Legend:** ⭐⭐⭐ = Critical, ⭐⭐ = Important, ⭐ = Nice-to-have

**Usage Notes:**

- **OWASP Top 10:** Essential for web apps, API security, developer education
- **CWE Top 25:** Universal for CVE tracking, vulnerability prioritization
- **CIS Controls:** Infrastructure, configuration management, IaC validation
- **NIST CSF 2.0:** Enterprise security posture, risk management, governance
- **PCI DSS 4.0:** Payment systems, cardholder data, compliance audits
- **MITRE ATT&CK:** Threat hunting, incident response, adversary emulation

---

## Matrix 4: Execution Mode × Use Case

This matrix shows the recommended execution mode for each use case.

| Use Case | CLI (native) | Docker (full) | Docker (slim) | Docker (alpine) | Wizard |
|----------|--------------|---------------|---------------|-----------------|--------|
| **Pre-Commit Hook** | ⭐⭐⭐ | ⭐⭐ | ⭐ | ⭐ | ❌ |
| **PR Gate (Standard)** | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ | ⭐⭐ | ⭐ |
| **PR Gate (Strict)** | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ | ⭐⭐ | ⭐ |
| **Nightly Audit** | ⭐⭐⭐ | ⭐⭐⭐ | ⭐ | ⭐ | ❌ |
| **Container Release** | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐ |
| **IaC Validation** | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ | ⭐⭐ | ⭐ |
| **Web App Scan** | ⭐⭐⭐ | ⭐⭐⭐ | ⭐ | ⭐ | ⭐ |
| **Compliance Audit** | ⭐⭐⭐ | ⭐⭐⭐ | ⭐ | ⭐ | ⭐ |
| **Secret Scanning** | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ | ⭐⭐ | ⭐⭐ |
| **CVE Monitoring** | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐ |
| **Fuzzing Campaign** | ⭐⭐⭐ | ⭐⭐ | ❌ | ❌ | ❌ |
| **Incident Response** | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ | ⭐⭐ | ⭐⭐⭐ |

**Legend:** ⭐⭐⭐ = Recommended, ⭐⭐ = Suitable, ⭐ = Works but not optimal, ❌ = Not recommended

**Execution Mode Decision Tree:**

```text
1. Is this a first-time user or demo?
   YES → Wizard (interactive, guided)
   NO → Continue to 2

2. Are you in a CI/CD pipeline?
   YES → Docker (full) [isolation, reproducibility]
   NO → Continue to 3

3. Do you need all 11 tools?
   YES → CLI (native) or Docker (full) [deep profile requires all tools]
   NO → Continue to 4

4. Do you need fast startup time?
   YES → CLI (native) [no container overhead]
   NO → Continue to 5

5. Do you want zero local installation?
   YES → Docker (slim or alpine) [minimal tool subset]
   NO → CLI (native)
```

**Container Variant Selection:**

- **Docker (full):** All 11 tools, maximum coverage, 2.5 GB image
- **Docker (slim):** 7 tools (balanced profile), 1.2 GB image
- **Docker (alpine):** 3 tools (fast profile), 500 MB image

**Wizard Use Cases:**

- First-time users learning JMo Security
- Demos and presentations
- Generating reusable configurations (Makefile, shell script, GitHub Actions workflow)
- Incident response (quick guided scan)

---

## Matrix 5: Industry Vertical × Recommended Configuration

This matrix shows tailored configurations for different industries.

| Industry | Use Case | Target Types | Tools | Profile | Fail Threshold | Compliance Focus |
|----------|----------|--------------|-------|---------|----------------|------------------|
| **Financial Services** | Payment API Security | Repositories, Images, URLs | trivy, syft, zap, semgrep, trufflehog | deep | MEDIUM | PCI DSS, NIST CSF, OWASP |
| **Healthcare** | HIPAA Compliance | Repositories, IaC, K8s | trivy, checkov, semgrep, trufflehog | deep | MEDIUM | NIST CSF, CIS Controls, PCI DSS |
| **SaaS Providers** | Multi-Tenant Security | All 6 types | All 11 tools | deep | LOW | OWASP, CWE, MITRE ATT&CK |
| **E-Commerce** | Customer Data Protection | Repositories, Images, URLs | trufflehog, noseyparker, trivy, zap | balanced | HIGH | PCI DSS, OWASP, CWE |
| **DevOps Tooling** | Supply Chain Security | Images, K8s, GitLab | trivy, syft, falco, trufflehog | balanced | HIGH | CWE, NIST CSF, MITRE ATT&CK |
| **Open Source Projects** | Vulnerability Disclosure | Repositories | trufflehog, semgrep, trivy, bandit | balanced | HIGH | OWASP, CWE |
| **Government/Defense** | Zero Trust Architecture | All 6 types | All 11 tools | deep | CRITICAL | NIST CSF, CIS Controls, MITRE ATT&CK |
| **Startups** | Fast Iteration, Low Friction | Repositories | trufflehog, semgrep, trivy | fast | CRITICAL | OWASP, CWE |

### Example: Financial Services (Payment API Security)

```yaml
# jmo.yml
profiles:
  finserv-payment-api:
    tools: [trivy, syft, zap, semgrep, trufflehog]
    threads: 2
    timeout: 900
    fail_on: "MEDIUM"
    per_tool:
      trivy:
        flags: ["--no-progress", "--severity", "MEDIUM,HIGH,CRITICAL"]
      zap:
        flags: ["-config", "spider.maxDuration=15", "-config", "api.disablekey=true"]
      trufflehog:
        flags: ["--only-verified"]
      semgrep:
        flags: ["--config", "p/owasp-top-ten", "--config", "p/security-audit"]
outputs: [json, md, html, sarif]
```

**Compliance Reports Generated:**

- `PCI_DSS_COMPLIANCE.md` — Requirements 6.2, 6.3, 11.3
- `COMPLIANCE_SUMMARY.md` — NIST CSF (ID.RA, PR.DS, DE.CM), OWASP Top 10 (A02, A03, A07)
- `attack-navigator.json` — MITRE ATT&CK coverage

**Command:**

```bash
jmo scan --repo ./payment-service --image payment-api:v1.0 --url https://api.example.com/payment --profile-name finserv-payment-api
jmo report ./results --profile
```

---

## Matrix 6: Team Size × Recommended Workflow

This matrix shows optimal workflows for different team structures.

| Team Size | Workflow | Execution Mode | Profile | Frequency | Compliance Reporting |
|-----------|----------|----------------|---------|-----------|---------------------|
| **Solo Developer** | Pre-commit hook | CLI (native) | fast | Every commit | Manual review |
| **Small Team (2-5)** | PR gate | Docker (slim) | balanced | Every PR | Automated SARIF upload |
| **Mid-Sized Team (6-20)** | PR gate + Nightly audit | Docker (full) | balanced + deep | PR + daily | Automated + weekly review |
| **Large Team (20-50)** | Multi-stage gates | Docker (full) | fast → balanced → deep | PR → merge → nightly | Automated + compliance dashboard |
| **Enterprise (50+)** | Centralized security team | Docker (full) | custom profiles | Continuous | Automated + quarterly audits |

### Example: Mid-Sized Team (6-20 Developers)

**Workflow:**

1. **Pre-Commit:** Developer runs `jmotools fast --repo .` locally (5 min)
2. **PR Gate:** CI runs `jmo scan --profile-name balanced` (15 min)
3. **Nightly Audit:** Scheduled job runs `jmo scan --profile-name deep` on all repos (60 min)
4. **Weekly Review:** Security team reviews `COMPLIANCE_SUMMARY.md` and `dashboard.html`

**GitHub Actions Workflow:**

```yaml
# .github/workflows/security.yml
name: Security Scanning

on:
  pull_request:
  schedule:
    - cron: '0 2 * * *'  # 2 AM UTC daily

jobs:
  pr-gate:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run balanced profile
        run: |
          docker run --rm -v $(pwd):/repo jmo-security:latest scan --repo /repo --profile-name balanced --fail-on HIGH
          docker run --rm -v $(pwd):/repo jmo-security:latest report /repo/results --profile
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results/summaries/findings.sarif

  nightly-audit:
    if: github.event_name == 'schedule'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run deep profile
        run: |
          docker run --rm -v $(pwd):/repo jmo-security:latest scan --repo /repo --profile-name deep --fail-on LOW
          docker run --rm -v $(pwd):/repo jmo-security:latest report /repo/results --profile
      - uses: actions/upload-artifact@v4
        with:
          name: compliance-reports
          path: results/summaries/
```

---

## Matrix 7: Severity Threshold × Use Case

This matrix shows recommended `--fail-on` thresholds for different use cases.

| Use Case | CRITICAL | HIGH | MEDIUM | LOW | INFO | Rationale |
|----------|----------|------|--------|-----|------|-----------|
| **Pre-Commit Hook** | ✅ | ❌ | ❌ | ❌ | ❌ | Fast feedback, block only showstoppers |
| **PR Gate (Standard)** | ✅ | ✅ | ❌ | ❌ | ❌ | Balance thoroughness and velocity |
| **PR Gate (Strict)** | ✅ | ✅ | ✅ | ❌ | ❌ | Production-ready code only |
| **Main Branch Merge** | ✅ | ✅ | ⚠️ | ❌ | ❌ | Stricter than PR, allow manual override |
| **Container Release** | ✅ | ✅ | ❌ | ❌ | ❌ | No critical/high CVEs in production |
| **Nightly Audit** | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ❌ | Informational, expected to fail |
| **Compliance Audit** | ✅ | ✅ | ✅ | ⚠️ | ❌ | Exhaustive review, manual triage |
| **Secret Scanning** | ✅ | ✅ | ❌ | ❌ | ❌ | Zero tolerance for secrets |
| **CVE Monitoring** | ✅ | ✅ | ❌ | ❌ | ❌ | Track exploitable vulnerabilities |

**Legend:** ✅ = Fail build, ⚠️ = Informational (exit 0), ❌ = Ignore

**Threshold Decision Tree:**

```text
1. Is this blocking a deployment/release?
   YES → Use HIGH or CRITICAL
   NO → Continue to 2

2. Is this blocking a merge to main?
   YES → Use MEDIUM or HIGH
   NO → Continue to 3

3. Is this a pre-commit check?
   YES → Use CRITICAL only
   NO → Continue to 4

4. Is this a nightly/periodic audit?
   YES → Use LOW or INFO (informational)
   NO → Use MEDIUM (default)
```

---

## Matrix 8: Tool-Specific Use Cases

This matrix shows when to use each tool and common configurations.

| Tool | Primary Use Case | Target Types | Common Flags | Expected Findings | False Positive Rate |
|------|------------------|--------------|--------------|-------------------|---------------------|
| **trufflehog** | Verified secret detection | Repos, GitLab | `--only-verified` | API keys, tokens, passwords | **5%** (verified only) |
| **noseyparker** | Deep secret scanning | Repos | `--max-matches-per-file 100` | Unverified secrets, patterns | **30-40%** |
| **semgrep** | Multi-language SAST | Repos | `--config p/security-audit` | Code smells, injection, XSS | **10-15%** |
| **bandit** | Python-specific SAST | Repos | `--severity-level high` | Python security issues | **20-30%** |
| **syft** | SBOM generation | Repos, Images | `-q` | Package inventory | **0%** (informational) |
| **trivy** | Universal vulnerability scanner | All types | `--severity HIGH,CRITICAL` | CVEs, misconfigs, secrets | **5-10%** |
| **checkov** | IaC policy enforcement | Repos, IaC | `--framework terraform` | IaC violations | **15-20%** |
| **hadolint** | Dockerfile best practices | Repos | `--ignore DL3008` | Dockerfile issues | **10-15%** |
| **zap** | DAST web scanning | URLs | `-config spider.maxDuration=10` | OWASP Top 10 | **20-30%** |
| **falco** | Runtime security | Repos, K8s | N/A | Suspicious runtime behavior | **5-10%** |
| **afl++** | Fuzzing | Repos | `-m none` | Crashes, hangs, memory errors | **Varies** |

**Tool Selection Guidelines:**

- **Secrets:** Start with trufflehog (verified only), add noseyparker for deep audits
- **SAST:** semgrep for all languages, bandit for Python-heavy projects
- **SCA:** trivy + syft (trivy finds CVEs, syft generates SBOM for enrichment)
- **IaC:** trivy (misconfigs) + checkov (policies)
- **Containers:** trivy + syft (minimum), add falco for runtime monitoring
- **Web:** zap (only option, configure spider duration based on site size)
- **Fuzzing:** afl++ (deep profile only, requires instrumented binaries)

---

## Conclusion

**Key Takeaways:**

1. **Start Small:** Use `fast` profile for pre-commit, `balanced` for PRs, `deep` for audits
2. **Match Use Case to Tools:** Don't run all 11 tools on every commit (5-8 min vs 30-60 min)
3. **Compliance First:** Define required frameworks (PCI DSS, NIST CSF) and work backwards
4. **Threshold Tuning:** CRITICAL for pre-commit, HIGH for PRs, MEDIUM for releases, LOW for audits
5. **Execution Mode:** Native CLI for speed, Docker for CI/CD isolation, Wizard for onboarding
6. **Target Types:** Scan all 6 types in nightly audits, focus on repos+images for PRs
7. **Team Workflows:** Solo → pre-commit, Small → PR gate, Mid → PR + nightly, Large → multi-stage gates

**Common Pitfalls:**

- ❌ Running deep profile on every PR (too slow, 30-60 min)
- ❌ Using `--fail-on LOW` for pre-commit (blocks developers on noise)
- ❌ Ignoring compliance reports (defeats purpose of JMo Security)
- ❌ Not tuning per-tool flags (zap spider duration, semgrep excludes)
- ❌ Scanning only repositories (missing containers, IaC, web vulnerabilities)

**Recommended Starter Configuration:**

```yaml
# jmo.yml
default_profile: balanced

profiles:
  fast:
    tools: [trufflehog, semgrep, trivy]
    threads: 8
    timeout: 300
    fail_on: "CRITICAL"

  balanced:
    tools: [trufflehog, semgrep, syft, trivy, checkov, hadolint, zap]
    threads: 4
    timeout: 600
    fail_on: "HIGH"

  deep:
    tools: [trufflehog, noseyparker, semgrep, bandit, syft, trivy, checkov, hadolint, zap, falco, afl++]
    threads: 2
    timeout: 1800
    retries: 1
    fail_on: "MEDIUM"

outputs: [json, md, html, sarif]
```

**Next Steps:**

1. Review [TESTING_MATRIX.md](.claude/TESTING_MATRIX.md) for test coverage gaps
2. Customize profiles in `jmo.yml` for your use cases
3. Run `jmotools wizard` to generate starter configurations
4. Integrate into CI/CD using [docs/examples/github-actions-docker.yml](../docs/examples/github-actions-docker.yml)
5. Review compliance reports weekly: `COMPLIANCE_SUMMARY.md`, `PCI_DSS_COMPLIANCE.md`, `attack-navigator.json`

---

**Matrix Generated:** 2025-10-19
**Next Review:** Quarterly (or when new tools/compliance frameworks added)
**Maintainer:** Claude Code (via jmo-security-repo/CLAUDE.md guidance)
