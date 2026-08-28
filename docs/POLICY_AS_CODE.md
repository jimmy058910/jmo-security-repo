# Policy-as-Code

JMo Security includes **Policy-as-Code** integration using [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) for automated security policy enforcement.

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

- ❌ FAIL: a CRITICAL or HIGH finding mapped to one of **five** critical
  requirements — and only those five:

  | Requirement | Subject |
  |---|---|
  | 2.2.4 | System security parameters |
  | 3.5.1 | Cryptographic key protection |
  | 4.2.1 | Strong cryptography for transmission |
  | 6.2.4 | Software security vulnerabilities |
  | 8.3.6 | Password/passphrase strength |

- ⚠️ WARN: a **MEDIUM or LOW** finding mapped to any PCI DSS requirement
- ✅ PASS: no CRITICAL or HIGH finding maps to one of the five

**A HIGH finding mapped to any other requirement produces neither a violation
nor a warning.** The warning rule matches MEDIUM and LOW only, so the gate is
narrower than "any finding mapped to PCI DSS" in both directions.
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

- ❌ FAIL: a CRITICAL or HIGH finding whose `risk.cwe` holds one of ten
  HIPAA-critical CWEs, reported against the 45 CFR 164.312 technical safeguard
  it breaches:

  | Safeguard | CWEs |
  |---|---|
  | 164.312(a)(1) Access Control | CWE-22, CWE-79, CWE-89, CWE-200, CWE-284 |
  | 164.312(a)(2)(i) Unique User ID | CWE-798 |
  | 164.312(a)(2)(iv) Encryption | CWE-326, CWE-327 |
  | 164.312(d) Person/Entity Authentication | CWE-306 |
  | 164.312(e)(1) Transmission Security | CWE-319 |

- ✅ PASS: no CRITICAL or HIGH finding carries any of those CWEs

**This gate reads `risk.cwe` and nothing else.** It does not consult
`compliance.nistCsf2_0`, so a HIGH finding tagged only with a NIST CSF control
passes, and a HIGH finding carrying `CWE-79` fails whether or not it has any
NIST mapping. Violations are counted per breached safeguard, so one finding
matching two mapped CWEs is two violations.

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

### Fields Available to a Policy

`input.findings[_]` is a CommonFinding v1.2.0 object
(`docs/schemas/common_finding.v1.json`). **Reading a field that is not there
is not an error in Rego -- the expression becomes undefined, the rule
silently does not match, and the policy answers PASS.** Two shipped policies
were inert for exactly this reason before v1.1.0, so the three traps below
are worth reading before writing a rule.

**Always present** (schema `required`):

| Field | Type | Notes |
|---|---|---|
| `id` | string | the dedup fingerprint; policies use it as `fingerprint` |
| `ruleId` | string | the tool's own rule identifier |
| `severity` | string | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`, upper-case |
| `tool.name`, `tool.version` | string | |
| `location.path` | string | |
| `message` | string | |
| `schemaVersion` | string | |

**Optional -- may be absent entirely.** `Finding.to_dict()` drops `None`
values, so an unset optional field has no key at all. Read these with
`object.get`, or a violation object that mentions one will be undefined and
the finding will vanish from `violations` while `allow` still fails:

```rego
# WRONG -- drops the whole violation when the finding has no remediation
violation := {"rule": finding.ruleId, "remediation": finding.remediation}

# RIGHT
violation := {"rule": finding.ruleId,
             "remediation": object.get(finding, "remediation", "")}
```

`remediation`, `title`, `description`, `references`, `tags`, `cvss`, `risk`,
`compliance`, `context`, `raw`, and `location.startLine` / `location.endLine`
are all optional.

**Three traps:**

1. **`risk.cwe` is an array of strings, in two spellings.** Adapters store
   either the bare id (`["CWE-798"]`) or the id with its description
   appended (`["CWE-79: Improper Neutralization ..."]`). Match on the
   prefix, never with `sprintf("CWE-%d", ...)` -- Go's `%d` on a non-integer
   produces `CWE-%!d(string=...)`, which matches nothing and turns the rule
   into a permanent PASS.

2. **`raw` is the tool's own record, unnormalised.** Field names there are
   the tool's, not JMo's: TruffleHog writes `Verified` with a capital V.
   Prefer the normalised field where one exists -- the same signal is on
   `tags` as `"verified"` / `"unverified"`.

3. **`compliance.*` is added by the report phase, not by adapters.** Its
   sub-objects are `owaspTop10_2021` (array of strings such as `A03:2021`),
   `pciDss4_0` (array of objects with `requirement`, `priority`,
   `description`), `cisControlsV8_1`, `nistCsf2_0`, `mitreAttack` and
   `cweTop25_2024`. A findings file assembled by hand rather than by
   `jmo report` will not have them.

> **Check a new rule against a findings file you know contains a violation
> and one you know does not.** A PASS over an input the rule cannot match is
> byte-identical to a PASS over a clean repository.

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
jmo policy validate my-policy

# Test policy with sample findings
jmo policy test my-policy --findings-file results/summaries/findings.json

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
   # Test policy with sample findings
   jmo policy test zero-secrets --findings-file results/summaries/findings.json
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
4. **Check every field the rule dereferences actually exists.** This is the
   most common cause and it is silent: an undefined dereference makes the
   rule not match, so the policy reports PASS with no error and no warning.

   ```bash
   # Ask OPA what the rule body binds, one expression at a time
   opa eval -d policies/builtin/zero-secrets.rego -i results/summaries/findings.json --format pretty 'input.findings[0].raw'
   ```

   See [Fields Available to a Policy](#fields-available-to-a-policy) for the
   optional fields and the `risk.cwe` / `raw` traps.

### Performance Issues

**Issue:** Policy evaluation is slower than the <300 ms budget

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

**Most of the cost is process creation, not policy evaluation.** Each call
to `evaluate_policies` spawns two OPA processes -- a version probe when the
engine is constructed, and the `opa eval` itself -- so the floor is whatever
your platform charges for starting a process twice, and it dominates.

Measured on Windows 11, opa 1.18.2, 15 runs per case, machine otherwise idle:

| Case | min | median | p90 | max |
|---|---:|---:|---:|---:|
| Small (2 findings, one policy) | 77 ms | 79 ms | 103 ms | 105 ms |
| Large (1000 findings, one policy) | 98 ms | 115 ms | 131 ms | 136 ms |
| One bare `opa version` spawn | - | 35 ms | - | - |

So ~70 ms of that 79 ms median is two process spawns, and going from 2
findings to 1000 costs only ~36 ms. **Scaling with finding count is cheap;
the per-invocation floor is not.** If you evaluate several policies, expect
roughly that floor once per policy.

Process creation is markedly cheaper on Linux and macOS, so these figures
are an upper bound rather than a universal characteristic. This section
previously reported 20-25 ms per policy and an average of 21.81 ms against a
`<100 ms` target -- numbers that cannot have come from Windows, and that the
benchmark suite could not have contradicted, because it was silently
skipping (it looked for `opa` on `PATH` only, and `jmo tools install opa`
writes to `~/.jmo/bin/`).

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

## Windows Troubleshooting

### OPA not on PATH after installation

On Windows, `choco install opa` or a manual binary install may not refresh the current shell's PATH. Symptoms: `opa version` returns "command not found" even though the binary exists.

```powershell
# Close the current terminal and open a new one, OR
refreshenv                    # chocolatey helper
# OR point JMo at the binary directly:
$env:OPA_PATH = "C:\Program Files\opa\opa.exe"
jmo ci --repo . --policy zero-secrets
```

### Rego file encoding issues

If a custom `.rego` policy file fails to parse with "unexpected character" errors on Windows, check that the file uses LF line endings and UTF-8 encoding (not UTF-8-BOM):

```powershell
# Normalize line endings in PowerShell
(Get-Content policies/custom.rego -Raw) -replace "`r`n","`n" | Set-Content -NoNewline -Encoding UTF8 policies/custom.rego
```

Git's `core.autocrlf=false` in a `.gitattributes` entry for `*.rego` prevents this from happening in the first place.

---

**Last Updated:** August 2026 | **JMo Security v1.0.8**
