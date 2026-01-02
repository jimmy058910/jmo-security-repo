# Sample Output Examples

**Version:** v1.0.0+ (December 2025)

These examples demonstrate JMo Security output formats using the `samples/fixtures/infra-demo` target.

---

## Quick Start

```bash
# Scan a target
jmo scan --repo samples/fixtures/infra-demo --results /tmp/jmo-demo

# View results
cat /tmp/jmo-demo/summaries/SUMMARY.md
open /tmp/jmo-demo/summaries/dashboard.html
```

---

## Output Formats (v1.0.0)

All v1.0.0+ outputs use a standardized metadata wrapper:

```json
{
  "meta": {
    "output_version": "1.0.0",
    "jmo_version": "1.0.0",
    "schema_version": "1.2.0",
    "timestamp": "2025-12-22T10:30:00Z",
    "scan_id": "abc123",
    "profile": "balanced",
    "tools": ["trivy", "semgrep", "checkov", "..."],
    "target_count": 1,
    "finding_count": 68,
    "platform": "linux"
  },
  "findings": [
    { "...": "CommonFinding objects" }
  ]
}
```

### Available Formats

| File | Format | Use Case |
|------|--------|----------|
| `findings.json` | JSON | Machine processing, API integration |
| `findings.sarif` | SARIF 2.1.0 | GitHub/GitLab code scanning |
| `findings.csv` | CSV | Excel, compliance reporting |
| `SUMMARY.md` | Markdown | PR comments, documentation |
| `dashboard.html` | HTML | Interactive browser viewing |
| `simple-report.html` | HTML | Email-compatible static report |

---

## Aggregated Summary (`summaries/SUMMARY.md`)

```markdown
# Security Summary

Total findings: 68 | CRITICAL: 3 | HIGH: 38 | MEDIUM: 9 | LOW: 16

## Top Risks by File

| File | Findings | Severity | Top Issue |
|------|----------|----------|-----------|
| infra-demo/secrets.json | 32 | HIGH | generic-api-key (32x) |
| infra-demo/Dockerfile | 4 | HIGH | missing-user |
| infra-demo/main.tf | 6 | CRITICAL | aws-vpc-no-public-egress-sgr (2x) |
| infra-demo/deployment.yaml | 3 | HIGH | run-as-non-root |

## By Severity

- CRITICAL: 3
- HIGH: 38
- MEDIUM: 9
- LOW: 16
- INFO: 2

## By Tool

- **trufflehog**: 32 findings (32 HIGH)
- **trivy**: 26 findings (3 CRITICAL, 16 HIGH, 4 MEDIUM, 3 LOW)
- **checkov**: 7 findings (7 HIGH)
- **hadolint**: 4 findings (4 LOW)
- **semgrep**: 3 findings (2 HIGH, 1 LOW)

## Remediation Priorities

1. **Rotate 32 exposed secrets** (HIGH) - See findings for rotation guide
2. **Fix aws-vpc-no-public-egress-sgr** (2 findings) - Review security group rules
3. **Harden IaC configurations** (13 findings) - Apply security templates
```

---

## Individual Tool Outputs (`individual-repos/*/`)

| Tool | Findings | Notes |
|------|----------|-------|
| trivy | 26 | Dockerfile + Kubernetes + Terraform misconfigurations |
| checkov | 7 | Terraform findings for unrestricted ingress/egress |
| hadolint | 4 | Dockerfile linting (package pinning, non-root user) |
| semgrep | 3 | Dockerfile USER, K8s runAsNonRoot, allowPrivilegeEscalation |
| trufflehog | 32 | Verified secrets detection |
| noseyparker | 0 | No additional secrets detected |
| syft | 0 | No SBOM artifacts (minimal fixture) |

---

## HTML Dashboard (`summaries/dashboard.html`)

Interactive React dashboard with:

- Severity cards with counts
- Filterable findings table
- Tool breakdown charts
- KEV-first sorting for critical vulnerabilities
- Dual-mode loading (inline for <=1000 findings, external JSON for larger scans)

---

## CSV Export (`summaries/findings.csv`)

```csv
# JMo Security Scan Results
# Version: 1.0.0
# Timestamp: 2025-12-22T10:30:00Z
# Profile: balanced
# Finding Count: 68

severity,ruleId,message,path,startLine,tool,category
HIGH,generic-api-key,API key detected,secrets.json,15,trufflehog,secrets
CRITICAL,aws-vpc-no-public-egress-sgr,Unrestricted egress,main.tf,42,trivy,iac
...
```

---

## Simple HTML Report (`summaries/simple-report.html`)

Email-compatible static HTML with inline CSS. Tested in:

- Gmail, Outlook, Apple Mail
- Thunderbird, Yahoo Mail, ProtonMail

Use case: Sending scan results to stakeholders who don't have dashboard access.

---

## SARIF Output (`summaries/findings.sarif`)

SARIF 2.1.0 compliant output for code scanning integration:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "JMo Security",
          "version": "1.0.0"
        }
      },
      "results": [...]
    }
  ]
}
```

Upload to GitHub: `gh code-scanning upload -r owner/repo -s findings.sarif`

---

## Quick Reference

| Need | File |
|------|------|
| Machine-readable findings | `findings.json` |
| GitHub code scanning | `findings.sarif` |
| Excel/spreadsheet | `findings.csv` |
| PR comments | `SUMMARY.md` |
| Interactive viewing | `dashboard.html` |
| Email reports | `simple-report.html` |
| Suppression tracking | `SUPPRESSIONS.md` |

---

**Documentation:** [docs/RESULTS_GUIDE.md](docs/RESULTS_GUIDE.md) for complete output format specification.
