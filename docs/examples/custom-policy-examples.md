# Custom Policy Examples

This guide provides **5 real-world custom policy examples** for JMo Security Policy-as-Code integration.

## Table of Contents

1. [SQL Injection Blocker](#1-sql-injection-blocker)
2. [Container Vulnerability Gate](#2-container-vulnerability-gate)
3. [CWE Top 25 Compliance](#3-cwe-top-25-compliance)
4. [License Compliance Policy](#4-license-compliance-policy)
5. [Cloud Misconfiguration Blocker](#5-cloud-misconfiguration-blocker)

---

## 1. SQL Injection Blocker

**Purpose:** Block all SQL injection vulnerabilities (OWASP A03:2021).

**Use Case:** Web applications, API backends, database integrations.

### Policy (`sql-injection-blocker.rego`)

```rego
package jmo.policy.sql_injection

import future.keywords.if
import future.keywords.in

metadata := {
    "name": "SQL Injection Blocker",
    "version": "1.0.0",
    "description": "Block all SQL injection vulnerabilities (OWASP A03:2021)",
    "author": "Security Team",
    "tags": ["sql", "injection", "owasp-a03"],
    "frameworks": ["OWASP Top 10", "CWE Top 25"],
}

default allow := false

allow if {
    count(sql_injection_findings) == 0
}

# SQL injection patterns
sql_patterns := ["sql-injection", "sqli", "A03:2021", "CWE-89"]

sql_injection_findings contains finding if {
    finding := input.findings[_]
    finding.severity in ["CRITICAL", "HIGH"]

    # Check message or OWASP compliance
    some pattern in sql_patterns
    contains(lower(finding.message), pattern)
}

sql_injection_findings contains finding if {
    finding := input.findings[_]
    finding.severity in ["CRITICAL", "HIGH"]

    # Check OWASP Top 10 mapping
    finding.compliance.owaspTop10_2021
    "A03:2021" in finding.compliance.owaspTop10_2021
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
        "remediation": "Use parameterized queries or prepared statements. Never concatenate user input into SQL strings.",
    }
}

message := msg if {
    count(violations) > 0
    msg := sprintf("🚨 BLOCKED: %d SQL injection vulnerabilities detected", [count(violations)])
} else := "✅ No SQL injection vulnerabilities detected"
```

### Usage

```bash
# Install policy
mkdir -p ~/.jmo/policies
cp sql-injection-blocker.rego ~/.jmo/policies/

# Validate syntax
opa check ~/.jmo/policies/sql-injection-blocker.rego

# Use in scans
jmo ci --repo . --policy sql-injection-blocker --fail-on-policy-violation
```

### Example Violation

```python
# Vulnerable code (app.py)
user_id = request.GET.get('user_id')
query = f"SELECT * FROM users WHERE id = {user_id}"  # ❌ CRITICAL: SQL Injection
cursor.execute(query)
```

**Remediation:**

```python
# Fixed code
user_id = request.GET.get('user_id')
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))  # ✅ Parameterized query
```

---

## 2. Container Vulnerability Gate

**Purpose:** Block HIGH/CRITICAL container vulnerabilities with EPSS ≥ 0.1.

**Use Case:** Kubernetes deployments, Docker images, container registries.

### Policy (`container-vulnerability-gate.rego`)

```rego
package jmo.policy.container_security

import future.keywords.if
import future.keywords.in

metadata := {
    "name": "Container Vulnerability Gate",
    "version": "1.0.0",
    "description": "Block HIGH/CRITICAL container vulnerabilities with high exploitability (EPSS ≥ 0.1)",
    "author": "DevSecOps Team",
    "tags": ["container", "docker", "kubernetes", "epss"],
    "frameworks": ["NIST CSF", "CIS Controls"],
}

default allow := false

allow if {
    count(container_vulnerabilities) == 0
}

# Container scanning tools
container_tools := ["trivy", "grype", "syft"]

container_vulnerabilities contains finding if {
    finding := input.findings[_]
    finding.severity in ["CRITICAL", "HIGH"]

    # Filter container scanning tools
    finding.tool.name in container_tools

    # Check EPSS score (exploitability)
    finding.epss.score >= 0.1
}

violations contains violation if {
    finding := container_vulnerabilities[_]
    epss_score := sprintf("%.2f", [finding.epss.score * 100])
    violation := {
        "fingerprint": finding.id,
        "severity": finding.severity,
        "tool": finding.tool.name,
        "path": finding.location.path,
        "line": finding.location.startLine,
        "message": sprintf("Container vulnerability (EPSS: %s%%): %s", [epss_score, finding.message]),
        "remediation": "Update base image or patch vulnerable package. Check EPSS score for exploitation likelihood.",
    }
}

message := msg if {
    count(violations) > 0
    msg := sprintf("🚨 BLOCKED: %d high-risk container vulnerabilities (EPSS ≥ 0.1)", [count(violations)])
} else := "✅ No high-risk container vulnerabilities detected"
```

### Usage

```bash
# Install policy
cp container-vulnerability-gate.rego ~/.jmo/policies/

# Scan container image
jmo scan --image nginx:latest --profile-name balanced
jmo report results/ --policy container-vulnerability-gate --fail-on-policy-violation
```

### Example Violation

```dockerfile
# Vulnerable Dockerfile
FROM ubuntu:18.04  # ❌ CRITICAL: Outdated base image with HIGH/CRITICAL CVEs
RUN apt-get update && apt-get install -y openssl=1.1.0  # ❌ Vulnerable package
```

**Remediation:**

```dockerfile
# Fixed Dockerfile
FROM ubuntu:24.04  # ✅ Latest LTS base image
RUN apt-get update && apt-get install -y openssl  # ✅ Latest patched version
```

---

## 3. CWE Top 25 Compliance

**Purpose:** Enforce CWE Top 25 2024 compliance.

**Use Case:** Compliance audits, secure coding standards, vulnerability management.

### Policy (`cwe-top-25.rego`)

```rego
package jmo.policy.cwe_top_25

import future.keywords.if
import future.keywords.in

metadata := {
    "name": "CWE Top 25 Compliance Policy",
    "version": "1.0.0",
    "description": "Block CWE Top 25 2024 vulnerabilities",
    "author": "Security Team",
    "tags": ["cwe", "compliance", "vulnerability-management"],
    "frameworks": ["CWE Top 25", "MITRE"],
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

    # Extract CWE entries
    cwe_entries := [entry |
        entry := finding.compliance.cweTop25_2024[_]
    ]
    cwe_list := concat(", ", cwe_entries)

    violation := {
        "fingerprint": finding.id,
        "severity": "CRITICAL",
        "tool": finding.tool.name,
        "path": finding.location.path,
        "line": finding.location.startLine,
        "message": sprintf("CWE Top 25 violation: %s (Mapped to: %s)", [finding.message, cwe_list]),
        "remediation": finding.remediation,
    }
}

message := msg if {
    count(violations) > 0
    msg := sprintf("❌ FAILED: %d CWE Top 25 2024 violations detected", [count(violations)])
} else := "✅ PASSED: No CWE Top 25 2024 violations detected"
```

### Usage

```bash
# Install policy
cp cwe-top-25.rego ~/.jmo/policies/

# Scan with CWE Top 25 policy
jmo ci --repo . --policy cwe-top-25 --fail-on-policy-violation --profile-name deep
```

---

## 4. License Compliance Policy

**Purpose:** Block findings from copyleft licenses (GPL, LGPL, AGPL).

**Use Case:** Commercial software, proprietary codebases, license compliance.

### Policy (`license-compliance.rego`)

```rego
package jmo.policy.license_compliance

import future.keywords.if
import future.keywords.in

metadata := {
    "name": "License Compliance Policy",
    "version": "1.0.0",
    "description": "Block copyleft licenses (GPL, LGPL, AGPL) in dependencies",
    "author": "Legal Team",
    "tags": ["license", "compliance", "legal"],
    "frameworks": ["License Compliance"],
}

default allow := false

allow if {
    count(violations) == 0
}

# Copyleft licenses to block
copyleft_licenses := ["GPL", "LGPL", "AGPL", "GPL-2.0", "GPL-3.0", "LGPL-2.1", "LGPL-3.0", "AGPL-3.0"]

violations contains violation if {
    finding := input.findings[_]
    finding.severity in ["HIGH", "MEDIUM"]

    # Check license field (from scancode, bearer, or custom scanners)
    finding.license
    some license in copyleft_licenses
    contains(upper(finding.license), license)

    violation := {
        "fingerprint": finding.id,
        "severity": "HIGH",
        "tool": finding.tool.name,
        "path": finding.location.path,
        "line": finding.location.startLine,
        "message": sprintf("Copyleft license detected: %s (License: %s)", [finding.message, finding.license]),
        "remediation": "Replace dependency with MIT/Apache/BSD licensed alternative or obtain legal approval",
    }
}

message := msg if {
    count(violations) > 0
    msg := sprintf("🚨 BLOCKED: %d copyleft license violations detected", [count(violations)])
} else := "✅ No copyleft license violations detected"
```

### Usage

```bash
# Scan with license compliance policy
jmo scan --repo . --profile-name deep  # Includes scancode, bearer
jmo report results/ --policy license-compliance --fail-on-policy-violation
```

---

## 5. Cloud Misconfiguration Blocker

**Purpose:** Block HIGH/CRITICAL cloud misconfigurations (AWS, Azure, GCP, K8s).

**Use Case:** IaC deployments, cloud security, DevSecOps.

### Policy (`cloud-misconfiguration-blocker.rego`)

```rego
package jmo.policy.cloud_misconfiguration

import future.keywords.if
import future.keywords.in

metadata := {
    "name": "Cloud Misconfiguration Blocker",
    "version": "1.0.0",
    "description": "Block HIGH/CRITICAL cloud misconfigurations (AWS, Azure, GCP, K8s)",
    "author": "Cloud Security Team",
    "tags": ["cloud", "aws", "azure", "gcp", "kubernetes", "iac"],
    "frameworks": ["CIS Controls", "NIST CSF", "Cloud Security"],
}

default allow := false

allow if {
    count(cloud_misconfigurations) == 0
}

# Cloud/IaC scanning tools
cloud_tools := ["checkov", "trivy", "prowler", "kubescape"]

cloud_misconfigurations contains finding if {
    finding := input.findings[_]
    finding.severity in ["CRITICAL", "HIGH"]

    # Filter cloud/IaC tools
    finding.tool.name in cloud_tools
}

violations contains violation if {
    finding := cloud_misconfigurations[_]

    # Extract CIS Controls if available
    cis_controls := ""
    finding.compliance.cisControlsV8_1
    count(finding.compliance.cisControlsV8_1) > 0
    cis_list := [c | c := finding.compliance.cisControlsV8_1[_]]
    cis_controls := sprintf(" (CIS Controls: %s)", [concat(", ", cis_list)])

    violation := {
        "fingerprint": finding.id,
        "severity": finding.severity,
        "tool": finding.tool.name,
        "path": finding.location.path,
        "line": finding.location.startLine,
        "message": sprintf("Cloud misconfiguration: %s%s", [finding.message, cis_controls]),
        "remediation": finding.remediation,
    }
}

message := msg if {
    count(violations) > 0
    msg := sprintf("🚨 BLOCKED: %d cloud misconfigurations detected", [count(violations)])
} else := "✅ No cloud misconfigurations detected"
```

### Usage

```bash
# Scan Terraform
jmo scan --terraform-state infrastructure.tfstate --profile-name balanced
jmo report results/ --policy cloud-misconfiguration-blocker --fail-on-policy-violation

# Scan Kubernetes manifests
jmo scan --k8s-manifest deployment.yaml --profile-name balanced
jmo report results/ --policy cloud-misconfiguration-blocker --fail-on-policy-violation
```

### Example Violation

```yaml
# Vulnerable Kubernetes deployment (deployment.yaml)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  containers:
    - name: app
      image: nginx:latest
      securityContext:
        privileged: true  # ❌ CRITICAL: Privileged container
```

**Remediation:**

```yaml
# Fixed deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  containers:
    - name: app
      image: nginx:latest
      securityContext:
        privileged: false  # ✅ Non-privileged
        runAsNonRoot: true
        readOnlyRootFilesystem: true
```

---

## Testing Custom Policies

### Test Workflow

1. **Create test findings file:**

   ```bash
   jmo scan --repo /path/to/test-repo --profile-name fast
   cp results/summaries/findings.json test-findings.json
   ```

2. **Test policy:**

   ```bash
   jmo policy test my-custom-policy --findings-file test-findings.json
   ```

3. **Validate syntax:**

   ```bash
   opa check ~/.jmo/policies/my-custom-policy.rego
   ```

4. **Benchmark performance:**

   ```bash
   pytest tests/performance/test_policy_performance.py -v -s
   ```

### Unit Test Example

Create `tests/policies/test_custom_policy.py`:

```python
import json
from pathlib import Path
import pytest
from scripts.core.reporters.policy_reporter import evaluate_policies

def test_sql_injection_blocker():
    """Test SQL injection blocker policy."""
    findings = [
        {
            "schemaVersion": "1.2.0",
            "id": "finding-1",
            "ruleId": "sql-injection",
            "severity": "HIGH",
            "tool": {"name": "semgrep", "version": "1.0.0"},
            "location": {"path": "app.py", "startLine": 10},
            "message": "SQL injection vulnerability detected",
            "compliance": {"owaspTop10_2021": ["A03:2021"]},
        }
    ]

    builtin_dir = Path("policies/builtin")
    user_dir = Path.home() / ".jmo" / "policies"

    results = evaluate_policies(findings, ["sql-injection-blocker"], builtin_dir, user_dir)

    # Should fail (violations detected)
    assert "sql-injection-blocker" in results
    assert not results["sql-injection-blocker"].passed
    assert len(results["sql-injection-blocker"].violations) > 0
```

Run test:

```bash
pytest tests/policies/test_custom_policy.py -v
```

---

## Additional Resources

- [Policy-as-Code Guide](../POLICY_AS_CODE.md)
- [Policy Workflow Examples](policy-workflows.md)
- [Built-in Policies Reference](../../policies/README.md)
- [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
- [Rego v1 Syntax](https://www.openpolicyagent.org/docs/latest/policy-language/#rego-v1)

---

## Support

- **GitHub Issues:** [jmo-security-repo/issues](https://github.com/jimmy058910/jmo-security-repo/issues)
- **Community Forum:** [GitHub Discussions](https://github.com/jimmy058910/jmo-security-repo/discussions)
