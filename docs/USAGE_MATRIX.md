# JMo Security Usage Type Matrix

**Generated:** 2025-12-22
**Purpose:** Real-world usage patterns mapped to tool combinations, compliance requirements, and execution modes

## Executive Summary

This matrix provides prescriptive guidance for selecting the right tools, profiles, and compliance frameworks for different security use cases.

**Key Dimensions:**

- **12 Use Cases:** Pre-commit, PR gate, nightly audit, container release, IaC validation, web app scan, compliance audit, secret scanning, CVE monitoring, fuzzing, incident response, third-party audit
- **6 Target Types:** Repositories, Container Images, IaC Files, Web URLs, GitLab Repos, Kubernetes Clusters
- **28 Tools:** Organized across 4 profiles
- **4 Profiles:** fast (8 tools, 5-10 min), slim (14 tools, 12-18 min), balanced (18 tools, 18-25 min), deep (28 tools, 40-70 min)
- **6 Compliance Frameworks:** OWASP Top 10, CWE Top 25, CIS Controls, NIST CSF, PCI DSS, MITRE ATT&CK

> **Canonical tool reference:** [PROFILES_AND_TOOLS.md](PROFILES_AND_TOOLS.md)

---

## Matrix 1: Use Case x Recommended Configuration

This matrix maps common security use cases to optimal tool configurations.

| Use Case | Target Types | Profile | Fail Threshold | Est. Duration | Primary Compliance |
|----------|--------------|---------|----------------|---------------|-------------------|
| **Pre-Commit Hook** | Repositories | fast | CRITICAL | 5-10 min | OWASP, CWE |
| **PR Gate (Standard)** | Repositories | balanced | HIGH | 18-25 min | OWASP, CWE, PCI DSS |
| **PR Gate (Strict)** | Repositories, Images | balanced | MEDIUM | 18-25 min | All 6 frameworks |
| **Nightly Audit** | All 6 types | deep | LOW | 40-70 min | All 6 frameworks |
| **Container Release** | Images, K8s | balanced | HIGH | 18-25 min | CWE, NIST CSF, PCI DSS |
| **IaC Validation** | IaC Files, Repositories | slim | HIGH | 12-18 min | CIS Controls, NIST CSF |
| **Web App Scan (DAST)** | URLs | balanced | HIGH | 18-25 min | OWASP, PCI DSS |
| **Compliance Audit** | Repositories, IaC | deep | MEDIUM | 40-70 min | All 6 frameworks |
| **Secret Scanning** | Repositories, GitLab | deep | CRITICAL | 40-70 min | MITRE ATT&CK, PCI DSS |
| **CVE Monitoring** | Images, K8s, Repositories | fast | HIGH | 5-10 min | CWE, NIST CSF |
| **Fuzzing Campaign** | Repositories | deep | MEDIUM | 40-70 min | CWE, MITRE ATT&CK |
| **Incident Response** | All 6 types | deep | INFO | 40-70 min | MITRE ATT&CK |

---

## Configuration Examples

### Use Case: Pre-Commit Hook

**Goal:** Fast feedback loop (< 10 min) blocking critical issues

**Command:**

```bash
jmo scan --repo . --profile fast --fail-on CRITICAL --human-logs
```

**Expected Output:**

- `findings.json`: 0-50 findings (critical secrets, high-severity CVEs)
- `SUMMARY.md`: Severity breakdown
- `dashboard.html`: Interactive view
- **Exit Code:** 1 if CRITICAL findings exist, 0 otherwise

---

### Use Case: PR Gate (Strict)

**Goal:** Comprehensive scanning for production PRs

**Command:**

```bash
jmo scan --repo . --image myapp:pr-123 --profile balanced --fail-on MEDIUM
jmo report ./results
```

**GitHub Actions Integration:**

```yaml
- name: Strict PR Gate
  run: |
    jmo scan --repo . --image ${{ env.IMAGE_TAG }} --profile balanced --fail-on MEDIUM
    jmo report ./results
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
jmo scan --image myapp:v1.2.3 --k8s-context prod --profile balanced --fail-on HIGH
jmo report ./results
```

**Compliance Focus:**

- **CWE Top 25:** CVE mappings to dangerous weaknesses
- **NIST CSF 2.0:** ID.RA (Risk Assessment), DE.CM (Continuous Monitoring)
- **PCI DSS 4.0:** Requirement 6.3 (Secure Development), 11.3 (Vulnerability Scans)

---

### Use Case: IaC Validation

**Goal:** Infrastructure-as-Code security and compliance

**Command:**

```bash
jmo scan --iac ./infrastructure --profile slim --fail-on HIGH
jmo report ./results
```

**Compliance Focus:**

- **CIS Controls v8.1:** IG2/IG3 controls for configuration management
- **NIST CSF 2.0:** PR.DS (Data Security), PR.AC (Access Control)
- **PCI DSS 4.0:** Requirement 2.2 (Configuration Standards)

---

### Use Case: Secret Scanning (Deep)

**Goal:** Comprehensive secret discovery with dual scanners

**Command:**

```bash
jmo scan --repos-dir ~/code --gitlab-repo myorg/backend --gitlab-token $TOKEN --profile deep --fail-on CRITICAL
jmo report ./results
```

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
  --iac infrastructure.tfstate \
  --url https://api.example.com \
  --gitlab-repo myorg/backend \
  --k8s-context prod \
  --k8s-all-namespaces \
  --profile deep \
  --fail-on LOW
jmo report ./results
```

**Expected Output:**

- `findings.json`: 500-2000 findings (all severities, all target types)
- `COMPLIANCE_SUMMARY.md`: All 6 frameworks
- `dashboard.html`: Interactive visualization
- **Exit Code:** 1 if LOW+ findings exist (informational)

**Recommended Schedule:** Daily at 2 AM UTC (low traffic hours)

---

## Matrix 2: Target Type x Primary Tools

This matrix shows the **essential tools** for each target type (minimum viable configuration).

| Target Type | Essential Tools | Secondary Tools | Coverage Area |
|-------------|-----------------|-----------------|---------------|
| **Repositories** | trufflehog, semgrep, trivy | All other SAST/SCA tools | Secrets, SAST, SCA |
| **Container Images** | trivy, syft | grype, cdxgen | CVEs, SBOM, secrets |
| **IaC Files** | trivy, checkov | prowler, kubescape | Misconfigurations, policy |
| **Web URLs** | nuclei, zap | akto (deep) | DAST, OWASP Top 10 |
| **GitLab Repos** | trufflehog, semgrep | Same as repositories | Secrets, SAST |
| **Kubernetes Clusters** | trivy, kubescape | prowler, falco | Misconfigs, runtime |

**Recommendation:** Use **essential tools** for fast/slim profiles, add **secondary tools** for balanced/deep profiles.

---

## Matrix 3: Compliance Framework x Use Case Priority

This matrix shows which compliance frameworks are most relevant for each use case.

| Use Case | OWASP Top 10 | CWE Top 25 | CIS Controls | NIST CSF 2.0 | PCI DSS 4.0 | MITRE ATT&CK |
|----------|--------------|------------|--------------|--------------|-------------|--------------|
| **Pre-Commit Hook** | High | High | Low | Low | Low | Low |
| **PR Gate (Standard)** | High | High | Medium | Medium | Medium | Low |
| **PR Gate (Strict)** | High | High | High | High | High | Medium |
| **Nightly Audit** | High | High | High | High | High | High |
| **Container Release** | Medium | High | Medium | High | High | Medium |
| **IaC Validation** | Medium | Medium | High | High | High | Medium |
| **Web App Scan** | High | Medium | Medium | Medium | High | Medium |
| **Compliance Audit** | High | High | High | High | High | High |
| **Secret Scanning** | Medium | Medium | Medium | Medium | High | High |
| **CVE Monitoring** | Medium | High | Medium | High | High | Medium |
| **Fuzzing Campaign** | Medium | High | Low | Medium | Medium | High |
| **Incident Response** | Medium | Medium | Medium | Medium | Medium | High |

---

## Matrix 4: Execution Mode x Use Case

This matrix shows the recommended execution mode for each use case.

| Use Case | CLI (native) | Docker (deep) | Docker (balanced) | Docker (slim) | Docker (fast) |
|----------|--------------|---------------|-------------------|---------------|---------------|
| **Pre-Commit Hook** | Recommended | Works | Works | Works | Recommended |
| **PR Gate (Standard)** | Recommended | Recommended | Recommended | Works | Works |
| **PR Gate (Strict)** | Recommended | Recommended | Recommended | Works | Not recommended |
| **Nightly Audit** | Recommended | Recommended | Not recommended | Not recommended | Not recommended |
| **Container Release** | Works | Recommended | Recommended | Works | Not recommended |
| **IaC Validation** | Recommended | Works | Works | Recommended | Works |
| **Web App Scan** | Recommended | Recommended | Recommended | Not recommended | Not recommended |
| **Compliance Audit** | Recommended | Recommended | Not recommended | Not recommended | Not recommended |
| **Secret Scanning** | Recommended | Recommended | Works | Works | Not recommended |
| **CVE Monitoring** | Recommended | Recommended | Recommended | Recommended | Recommended |
| **Fuzzing Campaign** | Recommended | Works | Not recommended | Not recommended | Not recommended |
| **Incident Response** | Recommended | Recommended | Works | Works | Not recommended |

**Execution Mode Decision Tree:**

```text
1. Is this a first-time user or demo?
   YES -> Use wizard: jmo wizard
   NO -> Continue to 2

2. Are you in a CI/CD pipeline?
   YES -> Docker (profile matching your needs)
   NO -> Continue to 3

3. Do you need all 28 tools?
   YES -> CLI (native) or Docker (deep)
   NO -> Continue to 4

4. Do you want fast startup time?
   YES -> CLI (native)
   NO -> Docker (matching profile)
```

---

## Matrix 5: Industry Vertical x Recommended Configuration

| Industry | Use Case | Target Types | Profile | Fail Threshold | Compliance Focus |
|----------|----------|--------------|---------|----------------|------------------|
| **Financial Services** | Payment API Security | Repos, Images, URLs | deep | MEDIUM | PCI DSS, NIST CSF, OWASP |
| **Healthcare** | HIPAA Compliance | Repos, IaC, K8s | deep | MEDIUM | NIST CSF, CIS Controls |
| **SaaS Providers** | Multi-Tenant Security | All 6 types | deep | LOW | OWASP, CWE, MITRE |
| **E-Commerce** | Customer Data Protection | Repos, Images, URLs | balanced | HIGH | PCI DSS, OWASP, CWE |
| **DevOps Tooling** | Supply Chain Security | Images, K8s, GitLab | balanced | HIGH | CWE, NIST CSF, MITRE |
| **Open Source Projects** | Vulnerability Disclosure | Repos | balanced | HIGH | OWASP, CWE |
| **Government/Defense** | Zero Trust Architecture | All 6 types | deep | CRITICAL | NIST CSF, CIS, MITRE |
| **Startups** | Fast Iteration | Repos | fast | CRITICAL | OWASP, CWE |

---

## Matrix 6: Team Size x Recommended Workflow

| Team Size | Workflow | Execution Mode | Profile | Frequency | Compliance Reporting |
|-----------|----------|----------------|---------|-----------|---------------------|
| **Solo Developer** | Pre-commit hook | CLI (native) | fast | Every commit | Manual review |
| **Small Team (2-5)** | PR gate | Docker (balanced) | balanced | Every PR | SARIF upload |
| **Mid-Sized Team (6-20)** | PR gate + Nightly | Docker (balanced/deep) | balanced + deep | PR + daily | Automated + weekly |
| **Large Team (20-50)** | Multi-stage gates | Docker (all) | fast -> balanced -> deep | PR -> merge -> nightly | Automated + dashboard |
| **Enterprise (50+)** | Centralized | Docker (deep) | custom profiles | Continuous | Automated + audits |

---

## Matrix 7: Severity Threshold x Use Case

| Use Case | CRITICAL | HIGH | MEDIUM | LOW | INFO | Rationale |
|----------|----------|------|--------|-----|------|-----------|
| **Pre-Commit Hook** | Fail | Pass | Pass | Pass | Pass | Fast feedback, block only showstoppers |
| **PR Gate (Standard)** | Fail | Fail | Pass | Pass | Pass | Balance thoroughness and velocity |
| **PR Gate (Strict)** | Fail | Fail | Fail | Pass | Pass | Production-ready code only |
| **Main Branch Merge** | Fail | Fail | Warn | Pass | Pass | Stricter than PR |
| **Container Release** | Fail | Fail | Pass | Pass | Pass | No critical/high CVEs in production |
| **Nightly Audit** | Warn | Warn | Warn | Warn | Pass | Informational, expected to fail |
| **Compliance Audit** | Fail | Fail | Fail | Warn | Pass | Exhaustive review |
| **Secret Scanning** | Fail | Fail | Pass | Pass | Pass | Zero tolerance for secrets |
| **CVE Monitoring** | Fail | Fail | Pass | Pass | Pass | Track exploitable vulnerabilities |

**Legend:** Fail = Exit code 1, Warn = Report only (exit 0), Pass = Ignore

---

## Matrix 8: Tool-Specific Use Cases

| Tool | Primary Use Case | Target Types | Common Flags | False Positive Rate |
|------|------------------|--------------|--------------|---------------------|
| **trufflehog** | Verified secret detection | Repos, GitLab | `--only-verified` | ~5% (verified) |
| **noseyparker** | Deep secret scanning | Repos | `--max-matches-per-file 100` | ~30-40% |
| **semgrep** | Multi-language SAST | Repos | `--config p/security-audit` | ~10-15% |
| **bandit** | Python-specific SAST | Repos | `--severity-level high` | ~20-30% |
| **syft** | SBOM generation | Repos, Images | `-q` | 0% (informational) |
| **trivy** | Universal vulnerability scanner | All types | `--severity HIGH,CRITICAL` | ~5-10% |
| **checkov** | IaC policy enforcement | Repos, IaC | `--framework terraform` | ~15-20% |
| **hadolint** | Dockerfile best practices | Repos | `--ignore DL3008` | ~10-15% |
| **nuclei** | Fast vulnerability scanner | URLs | N/A | ~10-15% |
| **zap** | DAST web scanning | URLs | `-config spider.maxDuration=10` | ~20-30% |
| **prowler** | Cloud security (AWS/Azure/GCP) | IaC, K8s | N/A | ~10-15% |
| **kubescape** | Kubernetes security | IaC, K8s | N/A | ~10-15% |
| **grype** | Vulnerability scanner | Repos, Images | N/A | ~5-10% |
| **bearer** | Data privacy SAST | Repos | N/A | ~15-20% |
| **horusec** | Multi-language SAST | Repos | N/A | ~20-25% |
| **dependency-check** | OWASP SCA | Repos | N/A | ~10-15% |
| **scancode** | License/copyright scanning | Repos | N/A | ~5% |
| **cdxgen** | CycloneDX SBOM | Repos, Images | N/A | 0% (informational) |
| **gosec** | Go security analyzer | Repos | N/A | ~15-20% |
| **yara** | Malware pattern detection | Repos | N/A | ~10-15% |
| **falco** | Runtime security | K8s | N/A | ~5-10% |
| **akto** | API security | URLs | N/A | ~15-20% |
| **afl++** | Coverage-guided fuzzing | Repos | `-m none` | Varies |
| **mobsf** | Mobile security | Repos | N/A | ~15-20% |
| **lynis** | System hardening audit | N/A | N/A | ~10-15% |

---

## Conclusion

**Key Takeaways:**

1. **Start Small:** Use `fast` profile for pre-commit, `balanced` for PRs, `deep` for audits
2. **Match Use Case to Profile:** Don't run all 28 tools on every commit
3. **Compliance First:** Define required frameworks and work backwards
4. **Threshold Tuning:** CRITICAL for pre-commit, HIGH for PRs, MEDIUM for releases
5. **Execution Mode:** Native CLI for speed, Docker for CI/CD isolation
6. **Target Types:** Scan all 6 types in nightly audits, focus on repos+images for PRs
7. **Team Workflows:** Solo -> pre-commit, Small -> PR gate, Mid -> PR + nightly

**Common Pitfalls:**

- Running deep profile on every PR (too slow, 40-70 min)
- Using `--fail-on LOW` for pre-commit (blocks developers on noise)
- Ignoring compliance reports (defeats purpose of security scanning)
- Not tuning per-tool flags (zap spider duration, semgrep excludes)
- Scanning only repositories (missing containers, IaC, web vulnerabilities)

**Recommended Starter Configuration:**

```yaml
# jmo.yml
default_profile: balanced

profiles:
  fast:
    tools: [trufflehog, semgrep, syft, trivy, checkov, hadolint, nuclei, shellcheck]
    timeout: 300
    fail_on: "CRITICAL"

  slim:
    tools: [trufflehog, semgrep, syft, trivy, checkov, hadolint, nuclei, shellcheck,
            prowler, kubescape, grype, bearer, horusec, dependency-check]
    timeout: 600
    fail_on: "HIGH"

  balanced:
    tools: [trufflehog, semgrep, syft, trivy, checkov, hadolint, nuclei, shellcheck,
            prowler, kubescape, grype, bearer, horusec, dependency-check,
            zap, scancode, cdxgen, gosec]
    timeout: 900
    fail_on: "HIGH"

  deep:
    timeout: 1800
    fail_on: "MEDIUM"
    # All 28 tools - see PROFILES_AND_TOOLS.md

outputs: [json, md, html, sarif]
```

---

## See Also

- [PROFILES_AND_TOOLS.md](PROFILES_AND_TOOLS.md) - Canonical tool lists and dependencies
- [TESTING_MATRIX.md](TESTING_MATRIX.md) - Test coverage analysis
- [USER_GUIDE.md](USER_GUIDE.md) - Complete usage reference
- [docs/examples/](examples/) - CI/CD workflow examples

---

**Matrix Generated:** 2025-12-22
**JMo Security:** v1.0.0
**Maintainer:** See [CONTRIBUTING.md](../CONTRIBUTING.md)
