# Policy-as-Code

JMo Security v1.0.0+ includes **Policy-as-Code** integration using [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) for automated security policy enforcement.

## Quick Start (5 Minutes)

### 1. Verify OPA Installation

```bash
opa version
# Expected: Version: 1.10.0+ (Rego v1 syntax)
```

If OPA is not installed:

```bash
# Linux/WSL
wget https://github.com/open-policy-agent/opa/releases/download/v1.10.0/opa_linux_amd64
chmod +x opa_linux_amd64
sudo mv opa_linux_amd64 /usr/local/bin/opa

# macOS (Homebrew)
brew install opa

# Verify
opa version
```

### 2. Run Scan with Policy Evaluation

```bash
# Scan with automatic policy evaluation
jmo scan --repo . --profile-name balanced
jmo report results/ --policy zero-secrets

# Or use wizard mode
jmo wizard --policy zero-secrets --policy owasp-top-10
```

### 3. View Policy Results

Policy results are written to `results/summaries/`:

- `POLICY_REPORT.md` — Human-readable policy summary
- `policy_results.json` — Machine-readable policy results
- `POLICY_SUMMARY.md` — Executive summary (pass/fail counts)

```bash
# View policy report
cat results/summaries/POLICY_REPORT.md

# Example output:
# Policy Evaluation Report
# ========================
#
# ✅ PASSED: zero-secrets (0 violations)
# ❌ FAILED: owasp-top-10 (3 violations)
#
# Violations:
# - A03:2021 - Injection (2 findings)
# - A01:2021 - Broken Access Control (1 finding)
```

### 4. Enable CI Policy Gating

```bash
# Fail CI if policy violations found
jmo ci --repo . --policy zero-secrets --fail-on-policy-violation

# Exit codes:
#   0 = All policies passed
#   1 = Policy violations found (when --fail-on-policy-violation set)
#   2 = Errors occurred
```

## Built-in Policies

JMo Security includes **5 built-in policies** for common security scenarios:

### 1. Zero Secrets (`zero-secrets`)

**Purpose:** Zero-tolerance policy for verified secrets in source code.

**Criteria:**

- ❌ FAIL: Any verified secret detected by TruffleHog, Nosey Parker, or semgrep-secrets
- ✅ PASS: Zero verified secrets found

**Use Case:** Pre-commit hooks, CI/CD gate, production deployments

**Example Violation:**

```python
# config.py
API_KEY = "sk-1234567890abcdef"  # ❌ CRITICAL: Verified secret
```

**Remediation:**

1. Rotate credentials immediately
2. Remove from version control history (`git filter-repo`, `BFG Repo-Cleaner`)
3. Use environment variables or secret managers (AWS Secrets Manager, HashiCorp Vault)

### 2. OWASP Top 10 (`owasp-top-10`)

**Purpose:** Enforce OWASP Top 10 2021 compliance.

**Criteria:**

- ❌ FAIL: HIGH/CRITICAL findings mapped to OWASP Top 10 categories
- ✅ PASS: Zero HIGH/CRITICAL OWASP Top 10 findings

**Covered Categories:**

- A01:2021 - Broken Access Control
- A02:2021 - Cryptographic Failures
- A03:2021 - Injection
- A04:2021 - Insecure Design
- A05:2021 - Security Misconfiguration
- A06:2021 - Vulnerable and Outdated Components
- A07:2021 - Identification and Authentication Failures
- A08:2021 - Software and Data Integrity Failures
- A09:2021 - Security Logging and Monitoring Failures
- A10:2021 - Server-Side Request Forgery (SSRF)

**Use Case:** Web application security, compliance audits, PCI DSS requirement 6.5

### 3. PCI DSS 4.0 (`pci-dss`)

**Purpose:** Payment Card Industry Data Security Standard compliance.

**Criteria:**

- ❌ FAIL: Any HIGH/CRITICAL finding mapped to PCI DSS requirements
- ✅ PASS: Zero HIGH/CRITICAL PCI DSS findings

**Key Requirements:**

- Requirement 3: Protect stored cardholder data
- Requirement 6: Develop secure systems and applications
- Requirement 8: Identify and authenticate access
- Requirement 11: Test security systems regularly

**Use Case:** E-commerce, payment processing, financial services

### 4. Production Hardening (`production-hardening`)

**Purpose:** Enforce production deployment best practices.

**Criteria:**

- ❌ FAIL: HIGH/CRITICAL findings in production-related categories:
  - Secrets/credentials
  - Misconfigurations
  - Vulnerabilities with EPSS ≥ 0.1 (exploitability risk)
  - CISA KEV (Known Exploited Vulnerabilities)
- ✅ PASS: Zero HIGH/CRITICAL production-blocking findings

**Use Case:** Pre-deployment validation, release gates, canary deployments

### 5. HIPAA Compliance (`hipaa-compliance`)

**Purpose:** Health Insurance Portability and Accountability Act compliance.

**Criteria:**

- ❌ FAIL: HIGH/CRITICAL findings related to:
  - Data encryption (NIST CSF PR.DS-1, PR.DS-2)
  - Access controls (PR.AC-1, PR.AC-3, PR.AC-4)
  - Audit logging (DE.AE-3, DE.CM-1)
  - Vulnerability management (ID.RA-1, DE.CM-8)
- ✅ PASS: Zero HIGH/CRITICAL HIPAA-related findings

**Use Case:** Healthcare applications, PHI handling, HIPAA audits

## Custom Policy Authoring

### Rego v1 Syntax Basics

JMo policies use **Rego v1** (OPA 1.0+). Key differences from legacy Rego:

```rego
# Import keywords explicitly
import future.keywords.if
import future.keywords.in

# Use 'if' keyword for rules
allow if {
    count(violations) == 0
}

# Use 'in' for membership tests
finding.severity in ["CRITICAL", "HIGH"]
```

### Policy Template

```rego
package jmo.policy.custom

import future.keywords.if
import future.keywords.in

metadata := {
    "name": "My Custom Policy",
    "version": "1.0.0",
    "description": "Enforce custom security requirements",
    "author": "Your Name",
    "tags": ["custom", "security"],
    "frameworks": ["NIST CSF"],
}

default allow := false

# Define your allow condition
allow if {
    count(violations) == 0
}

# Collect violations
violations contains violation if {
    finding := input.findings[_]
    finding.severity in ["CRITICAL", "HIGH"]
    # Add custom conditions here
    violation := {
        "fingerprint": finding.id,
        "severity": finding.severity,
        "tool": finding.tool.name,
        "path": finding.location.path,
        "line": finding.location.startLine,
        "message": finding.message,
        "remediation": "Custom remediation steps",
    }
}

# Policy message
message := msg if {
    count(violations) > 0
    msg := sprintf("Found %d violations", [count(violations)])
} else := "All checks passed"
```

### Example: Block SQL Injection

```rego
package jmo.policy.sql_injection

import future.keywords.if
import future.keywords.in

metadata := {
    "name": "SQL Injection Blocker",
    "version": "1.0.0",
    "description": "Block all SQL injection findings",
    "author": "Security Team",
    "tags": ["sql", "injection", "owasp-a03"],
}

default allow := false

allow if {
    count(sql_injection_findings) == 0
}

sql_injection_findings contains finding if {
    finding := input.findings[_]
    finding.severity in ["CRITICAL", "HIGH"]

    # Check for SQL injection patterns
    sqli_patterns := ["sql-injection", "sqli", "A03:2021"]
    some pattern in sqli_patterns
    contains(lower(finding.message), pattern)
}

violations contains violation if {
    finding := sql_injection_findings[_]
    violation := {
        "fingerprint": finding.id,
        "severity": "CRITICAL",
        "tool": finding.tool.name,
        "path": finding.location.path,
        "line": finding.location.startLine,
        "message": sprintf("SQL Injection: %s", [finding.message]),
        "remediation": "Use parameterized queries or prepared statements",
    }
}

message := msg if {
    count(violations) > 0
    msg := sprintf("🚨 BLOCKED: %d SQL injection vulnerabilities", [count(violations)])
} else := "✅ No SQL injection vulnerabilities"
```

### Installing Custom Policies

```bash
# Create user policies directory
mkdir -p ~/.jmo/policies

# Copy your policy
cp my-policy.rego ~/.jmo/policies/

# Validate policy syntax
opa check ~/.jmo/policies/my-policy.rego

# Test policy with OPA eval (jmo policy test not yet available in v1.0.0)
opa eval -d ~/.jmo/policies/my-policy.rego -i results/summaries/findings.json 'data.my_policy'

# Use in scans
jmo scan --repo . --profile-name balanced
jmo report results/ --policy my-policy
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan with Policy Gating

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install OPA
        run: |
          wget https://github.com/open-policy-agent/opa/releases/download/v1.10.0/opa_linux_amd64
          chmod +x opa_linux_amd64
          sudo mv opa_linux_amd64 /usr/local/bin/opa

      - name: Run JMo Security Scan
        run: |
          pip install jmo-security
          jmo ci \
            --repo . \
            --policy zero-secrets \
            --policy owasp-top-10 \
            --fail-on-policy-violation

      - name: Upload Policy Results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: policy-results
          path: |
            results/summaries/POLICY_REPORT.md
            results/summaries/policy_results.json
```

### GitLab CI

```yaml
security-scan:
  image: python:3.11
  before_script:
    - pip install jmo-security
    - wget https://github.com/open-policy-agent/opa/releases/download/v1.10.0/opa_linux_amd64
    - chmod +x opa_linux_amd64
    - mv opa_linux_amd64 /usr/local/bin/opa
  script:
    - |
      jmo ci \
        --repo . \
        --policy zero-secrets \
        --policy production-hardening \
        --fail-on-policy-violation
  artifacts:
    paths:
      - results/summaries/
    expire_in: 30 days
  only:
    - merge_requests
    - main
```

### Jenkins

```groovy
pipeline {
    agent any

    stages {
        stage('Install OPA') {
            steps {
                sh '''
                    wget https://github.com/open-policy-agent/opa/releases/download/v1.10.0/opa_linux_amd64
                    chmod +x opa_linux_amd64
                    sudo mv opa_linux_amd64 /usr/local/bin/opa
                '''
            }
        }

        stage('Security Scan') {
            steps {
                sh '''
                    pip install jmo-security
                    jmo ci \
                      --repo . \
                      --policy zero-secrets \
                      --policy owasp-top-10 \
                      --fail-on-policy-violation
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'results/summaries/*', fingerprint: true
        }
    }
}
```

## Configuration Reference

### jmo.yml Policy Section

```yaml
policy:
  # Enable policy evaluation
  enabled: true

  # Auto-evaluate policies after every report
  auto_evaluate: true

  # Default policies to evaluate (when no --policy flags)
  default_policies:
    - zero-secrets
    - owasp-top-10

  # Fail CI/CD on policy violations (default: false)
  fail_on_violation: false

# Profile-specific policy defaults
profiles:
  fast:
    policy:
      default_policies:
        - zero-secrets

  balanced:
    policy:
      default_policies:
        - zero-secrets
        - owasp-top-10

  deep:
    policy:
      default_policies:
        - zero-secrets
        - owasp-top-10
        - pci-dss
        - production-hardening
        - hipaa-compliance
```

### Environment Variables

Override policy configuration via environment variables:

```bash
# Enable/disable policy evaluation
export JMO_POLICY_ENABLED=true

# Auto-evaluate policies
export JMO_POLICY_AUTO_EVALUATE=true

# Default policies (comma-separated)
export JMO_POLICY_DEFAULT_POLICIES="zero-secrets,owasp-top-10"

# Fail on violations
export JMO_POLICY_FAIL_ON_VIOLATION=true
```

**Priority:** CLI flags > Environment variables > jmo.yml config

## Troubleshooting

### OPA Not Found

**Error:** `FileNotFoundError: OPA binary not found`

**Solution:**

```bash
# Verify OPA installation
which opa

# Install OPA if missing (see Quick Start)
# OR set OPA_PATH environment variable
export OPA_PATH=/custom/path/to/opa
```

### Policy Syntax Errors

**Error:** `RuntimeError: Policy evaluation failed: rego_parse_error`

**Solution:**

```bash
# Validate policy syntax
opa check policies/builtin/my-policy.rego

# Common issues:
# - Missing 'import future.keywords.if' statement
# - Using legacy Rego syntax (omit 'if' keyword)
# - Incorrect package name (must start with 'jmo.policy.')
```

### No Violations Detected (False Negative)

**Issue:** Policy passes but findings exist

**Debug Steps:**

1. **Check policy criteria:**

   ```bash
   # Manually test policy with OPA eval (jmo policy test not yet available in v1.0.0)
   opa eval -d policies/builtin/zero-secrets.rego -i results/summaries/findings.json 'data.zero_secrets'
   ```

2. **Verify finding schema:**

   ```bash
   # Ensure findings have required fields
   cat results/summaries/findings.json | jq '.findings[0]'
   # Required: schemaVersion, id, severity, tool, location, message
   ```

3. **Check severity filtering:**

   ```rego
   # Policy may only check HIGH/CRITICAL findings
   finding.severity in ["CRITICAL", "HIGH"]
   ```

### Performance Issues

**Issue:** Policy evaluation takes >100ms

**Solutions:**

1. **Optimize Rego queries:**

   ```rego
   # ❌ SLOW: Nested loops
   violation := input.findings[i]
   count([x | x := input.findings[j]; x.severity == "HIGH"]) > 0

   # ✅ FAST: Set comprehensions
   high_findings := {f | f := input.findings[_]; f.severity == "HIGH"}
   ```

2. **Run performance benchmarks:**

   ```bash
   pytest tests/performance/test_policy_performance.py -v -s
   ```

3. **Check OPA version:**

   ```bash
   # OPA 1.0+ (Rego v1) is 2-3x faster than 0.x
   opa version
   ```

## Performance Characteristics

Based on benchmarks with 5 built-in policies:

- **Small finding sets** (<100 findings): 20-25ms per policy
- **Large finding sets** (1000 findings): <500ms per policy
- **Average evaluation time:** 21.81ms (target: <100ms) ✅
- **Slowest policy:** 23.33ms (production-hardening)
- **Fastest policy:** 20.77ms (owasp-top-10)

Run your own benchmarks:

```bash
pytest tests/performance/test_policy_performance.py -v -s
```

## Additional Resources

- [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
- [Rego v1 Migration Guide](https://www.openpolicyagent.org/docs/latest/policy-language/#rego-v1)
- [JMo Security User Guide](USER_GUIDE.md)
- [Policy Workflow Examples](examples/policy-workflows.md)
- [Custom Policy Examples](examples/custom-policy-examples.md)

## Next Steps

1. [Install OPA](#1-verify-opa-installation) and validate version
2. [Run your first policy scan](#2-run-scan-with-policy-evaluation)
3. [Enable CI policy gating](#4-enable-ci-policy-gating)
4. [Write a custom policy](#custom-policy-authoring)
5. [Integrate with your CI/CD pipeline](#cicd-integration)
