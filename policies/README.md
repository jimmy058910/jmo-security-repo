# JMo Security Policy Marketplace

This directory contains **OPA (Open Policy Agent) policies** for automated security policy enforcement in JMo Security scans.

## Directory Structure

```text
policies/
├── builtin/                    # Official JMo policies (shipped with v1.0.0+)
│   ├── zero-secrets.rego       # Zero-tolerance verified secrets policy
│   ├── owasp-top-10.rego       # OWASP Top 10 2021 compliance
│   ├── pci-dss.rego            # PCI DSS 4.0 compliance
│   ├── production-hardening.rego  # Production deployment best practices
│   └── hipaa-compliance.rego   # HIPAA compliance policy
└── README.md                   # This file
```

**User Policies:** Install custom policies to `~/.jmo/policies/` (auto-discovered during evaluation)

## Built-in Policies Overview

### 1. Zero Secrets (`zero-secrets.rego`)

**Purpose:** Zero-tolerance policy for verified secrets in source code.

**Enforcement:**

- ❌ FAIL: Any verified secret detected by TruffleHog, Nosey Parker, or semgrep-secrets
- ✅ PASS: Zero verified secrets found

**Severity:** CRITICAL

**Use Cases:**

- Pre-commit hooks
- CI/CD gates
- Production deployments
- Security audits

**Example Violation:**

```python
# config.py
API_KEY = "sk-1234567890abcdef"  # ❌ CRITICAL: Verified secret detected
```

**Remediation:**

1. Rotate credentials immediately
2. Remove from Git history (`git filter-repo`, `BFG Repo-Cleaner`)
3. Use environment variables or secret managers (AWS Secrets Manager, HashiCorp Vault, 1Password)

### 2. OWASP Top 10 (`owasp-top-10.rego`)

**Purpose:** Enforce OWASP Top 10 2021 compliance.

**Enforcement:**

- ❌ FAIL: Any HIGH/CRITICAL finding mapped to OWASP Top 10 categories
- ✅ PASS: Zero HIGH/CRITICAL OWASP Top 10 findings

**Covered Categories:**

- A01:2021 - Broken Access Control
- A02:2021 - Cryptographic Failures
- A03:2021 - Injection (SQL, XSS, Command Injection)
- A04:2021 - Insecure Design
- A05:2021 - Security Misconfiguration
- A06:2021 - Vulnerable and Outdated Components
- A07:2021 - Identification and Authentication Failures
- A08:2021 - Software and Data Integrity Failures
- A09:2021 - Security Logging and Monitoring Failures
- A10:2021 - Server-Side Request Forgery (SSRF)

**Use Cases:**

- Web application security
- PCI DSS Requirement 6.5 compliance
- Security audits
- DevSecOps integration

### 3. PCI DSS 4.0 (`pci-dss.rego`)

**Purpose:** Payment Card Industry Data Security Standard v4.0 compliance.

**Enforcement:**

- ❌ FAIL: Any HIGH/CRITICAL finding mapped to PCI DSS requirements
- ✅ PASS: Zero HIGH/CRITICAL PCI DSS findings

**Key Requirements:**

- **Requirement 3:** Protect stored cardholder data (cryptography, encryption)
- **Requirement 6:** Develop secure systems and applications (OWASP Top 10, vulnerability management)
- **Requirement 8:** Identify and authenticate access (MFA, password policies)
- **Requirement 11:** Test security systems regularly (vulnerability scanning, penetration testing)

**Use Cases:**

- E-commerce platforms
- Payment processing systems
- Financial services
- Compliance audits (QSA reviews)

### 4. Production Hardening (`production-hardening.rego`)

**Purpose:** Enforce production deployment best practices.

**Enforcement:**

- ❌ FAIL: HIGH/CRITICAL findings in production-blocking categories:
  - Secrets/credentials
  - Misconfigurations (Dockerfile, K8s, Terraform)
  - Vulnerabilities with EPSS ≥ 0.1 (high exploitability)
  - CISA KEV (Known Exploited Vulnerabilities)
- ✅ PASS: Zero HIGH/CRITICAL production-blocking findings

**Use Cases:**

- Pre-deployment validation gates
- Release pipelines
- Canary deployments
- Production security baselines

### 5. HIPAA Compliance (`hipaa-compliance.rego`)

**Purpose:** Health Insurance Portability and Accountability Act compliance.

**Enforcement:**

- ❌ FAIL: HIGH/CRITICAL findings related to HIPAA security rules:
  - Data encryption (NIST CSF PR.DS-1, PR.DS-2)
  - Access controls (PR.AC-1, PR.AC-3, PR.AC-4)
  - Audit logging (DE.AE-3, DE.CM-1)
  - Vulnerability management (ID.RA-1, DE.CM-8)
- ✅ PASS: Zero HIGH/CRITICAL HIPAA-related findings

**Use Cases:**

- Healthcare applications (EMR, EHR, patient portals)
- PHI (Protected Health Information) handling systems
- HIPAA audits and assessments
- Business Associate Agreement (BAA) compliance

## Custom Policy Development Guide

### Prerequisites

1. **Install OPA 1.0+** (Rego v1 syntax):

   ```bash
   # Linux/WSL
   wget https://github.com/open-policy-agent/opa/releases/download/v1.10.0/opa_linux_amd64
   chmod +x opa_linux_amd64
   sudo mv opa_linux_amd64 /usr/local/bin/opa

   # macOS (Homebrew)
   brew install opa

   # Verify
   opa version  # Expected: 1.10.0+
   ```

2. **Understand CommonFinding schema** (v1.2.0):

   See [docs/schemas/common_finding.v1.json](../docs/schemas/common_finding.v1.json) for complete schema reference.

   **Key Fields:**
   - `schemaVersion`: "1.2.0"
   - `id`: Fingerprint (stable across scans)
   - `severity`: CRITICAL/HIGH/MEDIUM/LOW/INFO
   - `tool`: {name, version}
   - `location`: {path, startLine, endLine}
   - `message`: Human-readable description
   - `compliance`: {owaspTop10_2021, cweTop25_2024, cisControlsV8_1, nistCsf2_0, pciDss4_0, mitreAttack}

### Policy Structure Template

```rego
package jmo.policy.<policy-name>

import future.keywords.if
import future.keywords.in

# Policy metadata (required)
metadata := {
    "name": "Policy Display Name",
    "version": "1.0.0",
    "description": "Brief description of what this policy enforces",
    "author": "Your Name or Organization",
    "tags": ["tag1", "tag2"],
    "frameworks": ["OWASP", "NIST CSF", "CIS Controls"],
}

# Default deny (required)
default allow := false

# Allow condition (required)
allow if {
    count(violations) == 0
}

# Violations collection (required)
violations contains violation if {
    finding := input.findings[_]

    # Add your filtering logic here
    finding.severity in ["CRITICAL", "HIGH"]

    # Create violation object
    violation := {
        "fingerprint": finding.id,
        "severity": finding.severity,
        "tool": finding.tool.name,
        "path": finding.location.path,
        "line": finding.location.startLine,
        "message": finding.message,
        "remediation": "Remediation steps here",
    }
}

# Policy message (required)
message := msg if {
    count(violations) > 0
    msg := sprintf("Policy FAILED: %d violations found", [count(violations)])
} else := "Policy PASSED: No violations found"
```

### Example Policies

#### Example 1: Block Container Vulnerabilities

```rego
package jmo.policy.container_security

import future.keywords.if
import future.keywords.in

metadata := {
    "name": "Container Security Policy",
    "version": "1.0.0",
    "description": "Block HIGH/CRITICAL container vulnerabilities",
    "author": "DevSecOps Team",
    "tags": ["container", "docker", "kubernetes"],
}

default allow := false

allow if {
    count(container_vulnerabilities) == 0
}

container_vulnerabilities contains finding if {
    finding := input.findings[_]
    finding.severity in ["CRITICAL", "HIGH"]

    # Filter container scanning tools
    finding.tool.name in ["trivy", "grype", "syft"]
}

violations contains violation if {
    finding := container_vulnerabilities[_]
    violation := {
        "fingerprint": finding.id,
        "severity": finding.severity,
        "tool": finding.tool.name,
        "path": finding.location.path,
        "line": finding.location.startLine,
        "message": sprintf("Container vulnerability: %s", [finding.message]),
        "remediation": "Update base image or patch vulnerable package",
    }
}

message := msg if {
    count(violations) > 0
    msg := sprintf("🚨 BLOCKED: %d container vulnerabilities", [count(violations)])
} else := "✅ No container vulnerabilities"
```

#### Example 2: Enforce CWE Top 25 Compliance

```rego
package jmo.policy.cwe_top_25

import future.keywords.if
import future.keywords.in

metadata := {
    "name": "CWE Top 25 Policy",
    "version": "1.0.0",
    "description": "Block CWE Top 25 2024 vulnerabilities",
    "author": "Security Team",
    "tags": ["cwe", "compliance"],
}

default allow := false

allow if {
    count(cwe_top_25_findings) == 0
}

cwe_top_25_findings contains finding if {
    finding := input.findings[_]
    finding.severity in ["CRITICAL", "HIGH"]

    # Check if finding has CWE Top 25 mapping
    finding.compliance.cweTop25_2024
    count(finding.compliance.cweTop25_2024) > 0
}

violations contains violation if {
    finding := cwe_top_25_findings[_]
    cwe_entries := concat(", ", finding.compliance.cweTop25_2024)
    violation := {
        "fingerprint": finding.id,
        "severity": "CRITICAL",
        "tool": finding.tool.name,
        "path": finding.location.path,
        "line": finding.location.startLine,
        "message": sprintf("CWE Top 25 violation: %s (%s)", [finding.message, cwe_entries]),
        "remediation": finding.remediation,
    }
}

message := msg if {
    count(violations) > 0
    msg := sprintf("❌ FAILED: %d CWE Top 25 violations", [count(violations)])
} else := "✅ PASSED: No CWE Top 25 violations"
```

### Development Workflow

1. **Create policy file:**

   ```bash
   mkdir -p ~/.jmo/policies
   vim ~/.jmo/policies/my-policy.rego
   ```

2. **Validate syntax:**

   ```bash
   opa check ~/.jmo/policies/my-policy.rego
   ```

3. **Test with sample findings:**

   ```bash
   # Create test findings file
   jmo scan --repo /path/to/test-repo --profile-name fast
   jmo report results/ --policy my-policy

   # OR use jmo policy test command
   jmo policy test my-policy --findings-file results/summaries/findings.json
   ```

4. **Benchmark performance:**

   ```bash
   # Ensure policy evaluation <100ms
   pytest tests/performance/test_policy_performance.py -v -s
   ```

5. **Integrate into CI/CD:**

   ```bash
   jmo ci --repo . --policy my-policy --fail-on-policy-violation
   ```

## Policy Contribution Guidelines

### Submission Requirements

To contribute a policy to the official JMo policy marketplace:

1. **Policy Quality Standards:**
   - ✅ Use Rego v1 syntax (`import future.keywords.if`, `import future.keywords.in`)
   - ✅ Include complete metadata block
   - ✅ Pass `opa check` validation
   - ✅ Include remediation guidance in violations
   - ✅ Performance: <100ms average evaluation time

2. **Documentation:**
   - ✅ Policy purpose and use cases
   - ✅ Enforcement criteria (FAIL/PASS conditions)
   - ✅ Example violations
   - ✅ Remediation steps
   - ✅ Target frameworks (OWASP, NIST CSF, PCI DSS, etc.)

3. **Testing:**
   - ✅ Unit tests with sample findings
   - ✅ Integration tests with JMo CLI
   - ✅ Performance benchmarks

4. **Real-World Validation:**
   - ✅ Tested on 3+ real codebases
   - ✅ False positive rate <5%
   - ✅ No false negatives on known vulnerable code

### Submission Process

1. Fork [jmo-security-repo](https://github.com/jimmy058910/jmo-security-repo)
2. Add policy to `policies/builtin/`
3. Add tests to `tests/policies/`
4. Update `docs/POLICY_AS_CODE.md` with policy documentation
5. Create pull request with:
   - Policy rationale
   - Test coverage report
   - Performance benchmark results
   - Real-world validation summary

### Review Criteria

Pull requests will be reviewed for:

- **Security correctness:** Does the policy accurately detect violations?
- **Performance:** Does it meet the <100ms target?
- **Usability:** Is the policy easy to understand and use?
- **Documentation:** Is the policy well-documented?
- **Compatibility:** Does it work with all JMo scan modes (CLI, Docker, Wizard)?

### Community Policies

Policies not yet accepted into `policies/builtin/` can be shared via:

- **GitHub Gist:** Share policy as gist, add to [Community Policy Index](https://github.com/jimmy058910/jmo-security-repo/wiki/Community-Policies)
- **User repositories:** Create `~/.jmo/policies/` directory and install manually

## Performance Best Practices

### Optimization Techniques

1. **Use set comprehensions instead of loops:**

   ```rego
   # ❌ SLOW: Nested loops
   violation := input.findings[i]
   count([x | x := input.findings[j]; x.severity == "HIGH"]) > 0

   # ✅ FAST: Set comprehension
   high_findings := {f | f := input.findings[_]; f.severity == "HIGH"}
   ```

2. **Avoid redundant computations:**

   ```rego
   # ❌ SLOW: Re-compute secret_tools in every iteration
   violations contains violation if {
       finding := input.findings[_]
       finding.tool.name in ["trufflehog", "noseyparker", "semgrep-secrets"]
   }

   # ✅ FAST: Define once at module level
   secret_tools := ["trufflehog", "noseyparker", "semgrep-secrets"]

   violations contains violation if {
       finding := input.findings[_]
       finding.tool.name in secret_tools
   }
   ```

3. **Filter early, compute late:**

   ```rego
   # ❌ SLOW: Compute compliance checks on all findings
   violations contains violation if {
       finding := input.findings[_]
       cwe_entries := concat(", ", finding.compliance.cweTop25_2024)
       finding.severity in ["CRITICAL", "HIGH"]  # Filter too late
   }

   # ✅ FAST: Filter first, then compute
   violations contains violation if {
       finding := input.findings[_]
       finding.severity in ["CRITICAL", "HIGH"]  # Filter early
       cwe_entries := concat(", ", finding.compliance.cweTop25_2024)
   }
   ```

### Performance Benchmarks

Run benchmarks to validate performance:

```bash
pytest tests/performance/test_policy_performance.py -v -s

# Expected output:
# Policy Evaluation Performance:
#   production-hardening       23.33ms
#   zero-secrets               22.49ms
#   hipaa-compliance           21.26ms
#   pci-dss                    21.19ms
#   owasp-top-10               20.77ms
#
# Average: 21.81ms ✅ PASS (target: <100ms)
```

## Additional Resources

- [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
- [Rego v1 Migration Guide](https://www.openpolicyagent.org/docs/latest/policy-language/#rego-v1)
- [JMo Policy-as-Code Guide](../docs/POLICY_AS_CODE.md)
- [CommonFinding Schema Reference](../docs/schemas/common_finding.v1.json)
- [Policy Workflow Examples](../docs/examples/policy-workflows.md)
- [Custom Policy Examples](../docs/examples/custom-policy-examples.md)

## Support

- **GitHub Issues:** [jmo-security-repo/issues](https://github.com/jimmy058910/jmo-security-repo/issues)
- **Community Forum:** [GitHub Discussions](https://github.com/jimmy058910/jmo-security-repo/discussions)
- **Policy Contributions:** [Contributing Guide](../CONTRIBUTING.md)
