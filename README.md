# JMo Security Audit Tool Suite

![JMo Security Audit Tool Suite](assets/jmo-logo.png)

[![Tests](https://github.com/jimmy058910/jmo-security-repo/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/jimmy058910/jmo-security-repo/actions/workflows/ci.yml?query=branch%3Amain)
[![codecov](https://codecov.io/gh/jimmy058910/jmo-security-repo/branch/main/graph/badge.svg)](https://app.codecov.io/gh/jimmy058910/jmo-security-repo)
[![PyPI version](https://img.shields.io/pypi/v/jmo-security.svg)](https://pypi.org/project/jmo-security/)
[![Python Versions](https://img.shields.io/pypi/pyversions/jmo-security.svg)](https://pypi.org/project/jmo-security/)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](https://opensource.org/licenses/MIT)
[![Docker Pulls](https://img.shields.io/docker/pulls/jmogaming/jmo-security)](https://hub.docker.com/r/jmogaming/jmo-security)
[![GitHub Stars](https://img.shields.io/github/stars/jimmy058910/jmo-security-repo?style=social)](https://github.com/jimmy058910/jmo-security-repo)

**A terminal-first security audit toolkit orchestrating 28 scanners with unified CLI, normalized outputs, and interactive HTML dashboard.**

[![Newsletter](https://img.shields.io/badge/Newsletter-Subscribe-667eea)](https://jmotools.com/subscribe.html)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-Support-ff5e5b?logo=ko-fi&logoColor=white)](https://ko-fi.com/jmogaming)
[![GitHub Sponsors](https://img.shields.io/badge/Sponsor-GitHub-ea4aaa?logo=github&logoColor=white)](https://github.com/sponsors/jimmy058910)

---

## Overview

JMo Security is an automated security audit framework for scanning code repositories, container images, infrastructure-as-code, web applications, GitLab repos, and Kubernetes clusters. It orchestrates multiple industry-standard security tools with unified reporting and cross-tool deduplication.

> **Origin Story:** Built as my capstone project for **Institute of Data x Michigan Tech University's Cybersecurity Bootcamp** (graduated October 2025). Now a production-grade security platform. **Actively seeking cybersecurity/DevSecOps roles** - let's connect!

---

## Key Features

- **28 Security Scanners** - Secrets, SAST, SBOM, SCA, IaC, DAST, and more
- **6 Target Types** - Repos, images, IaC files, URLs, GitLab, Kubernetes
- **Unified Output** - JSON, SARIF, Markdown, HTML dashboard
- **Cross-Tool Deduplication** - 30-40% noise reduction
- **SQLite History** - Track security posture over time
- **Machine-Readable Diffs** - Compare scans, detect regressions
- **Statistical Trends** - Mann-Kendall analysis, security scores
- **Policy-as-Code** - OPA-based security policies
- **AI Remediation** - MCP integration for Copilot/Claude
- **SLSA Attestation** - Supply chain security compliance
- **6 Compliance Frameworks** - OWASP, CWE, NIST, PCI DSS, CIS, MITRE

---

## Get Started

| Goal | Action |
|------|--------|
| **Scan now (Docker)** | `docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan` |
| **Install CLI** | `pip install jmo-security` |
| **Guided setup** | `jmotools wizard` |
| **Full guide** | [QUICKSTART.md](QUICKSTART.md) |

### Quick Example

```bash
# Install
pip install jmo-security

# Scan a repository
jmo scan --repo ./myapp --profile balanced --human-logs

# View results
cat results/summaries/SUMMARY.md
open results/summaries/dashboard.html
```

### Docker (Zero Installation)

```bash
docker pull ghcr.io/jimmy058910/jmo-security:latest
docker run --rm -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results-dir /scan/results --profile balanced --human-logs
```

---

## Security Tools

28 scanners across 11 categories:

| Category | Tools |
|----------|-------|
| **Secrets** | TruffleHog (verified), Nosey Parker, Semgrep-Secrets |
| **SAST** | Semgrep, Bandit, Gosec, Horusec |
| **SBOM** | Syft, CDXgen, ScanCode |
| **SCA** | Trivy, Grype, OSV-Scanner, Dependency-Check |
| **IaC** | Checkov, Checkov-CICD |
| **Cloud/CSPM** | Prowler, Kubescape |
| **DAST** | OWASP ZAP, Nuclei |
| **Dockerfile** | Hadolint |
| **Malware** | YARA |
| **System** | Lynis |
| **Runtime** | Trivy-RBAC, Falco, AFL++ |

**Tool details:** [docs/USER_GUIDE.md#tool-overview](docs/USER_GUIDE.md#tool-overview)

---

## Scan Profiles

| Profile | Tools | Time | Use Case |
|---------|-------|------|----------|
| `fast` | 8 | 5-10 min | Pre-commit, PR validation |
| `balanced` | 21 | 18-25 min | CI/CD pipelines |
| `deep` | 28 | 40-70 min | Comprehensive audits |

---

## Output Formats

All findings normalized to CommonFinding schema v1.2.0:

| Format | File | Use Case |
|--------|------|----------|
| HTML | `dashboard.html` | Interactive visual dashboard |
| Markdown | `SUMMARY.md` | Human-readable overview |
| JSON | `findings.json` | Automation, scripting |
| SARIF | `findings.sarif` | GitHub/GitLab Code Scanning |
| YAML | `findings.yaml` | Alternative data format |

**Sample outputs:** [SAMPLE_OUTPUTS.md](SAMPLE_OUTPUTS.md)

---

## Multi-Target Scanning

Scan 6 target types in one unified workflow:

```bash
# Repository
jmo scan --repo ./myapp

# Container image
jmo scan --image nginx:latest

# IaC files
jmo scan --terraform-state terraform.tfstate

# Live web app
jmo scan --url https://example.com --tools zap

# GitLab repos
jmo scan --gitlab-group myorg --gitlab-token $TOKEN

# Kubernetes cluster
jmo scan --k8s-context prod --k8s-all-namespaces

# Everything at once
jmo scan --repo . --image myapp:latest --url https://myapp.com
```

**Complete guide:** [docs/USER_GUIDE.md#multi-target-scanning](docs/USER_GUIDE.md#multi-target-scanning)

---

## Key Commands

```bash
# Interactive wizard
jmotools wizard

# Scan with profile
jmo scan --repos-dir ~/repos --profile balanced

# CI mode (scan + gate)
jmo ci --repo . --fail-on HIGH

# Compare scans
jmo diff baseline/ current/ --format md

# View history
jmo history list

# Analyze trends
jmo trends analyze --days 30

# Generate reports
jmo report ./results
```

**Full CLI reference:** [docs/USER_GUIDE.md](docs/USER_GUIDE.md)

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Security Scan
  run: |
    docker run --rm -v ${{ github.workspace }}:/scan \
      ghcr.io/jimmy058910/jmo-security:latest \
      ci --repo /scan --fail-on HIGH --profile balanced

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results/summaries/findings.sarif
```

### GitLab CI

```yaml
security_scan:
  image: ghcr.io/jimmy058910/jmo-security:latest
  script:
    - jmo ci --repo . --fail-on HIGH --profile balanced
  artifacts:
    reports:
      sast: results/summaries/findings.sarif
```

**More examples:** [docs/examples/](docs/examples/)

---

## Documentation

### Getting Started

| Document | Purpose |
|----------|---------|
| [QUICKSTART.md](QUICKSTART.md) | 5-minute installation guide |
| [docs/DOCKER_README.md](docs/DOCKER_README.md) | Docker usage guide |
| [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | Comprehensive reference |

### Features

| Document | Purpose |
|----------|---------|
| [docs/RESULTS_GUIDE.md](docs/RESULTS_GUIDE.md) | Understanding findings |
| [docs/POLICY_AS_CODE.md](docs/POLICY_AS_CODE.md) | OPA security policies |
| [docs/SCHEDULE_GUIDE.md](docs/SCHEDULE_GUIDE.md) | Automated scheduling |
| [docs/MCP_SETUP.md](docs/MCP_SETUP.md) | AI remediation setup |

### Reference

| Document | Purpose |
|----------|---------|
| [docs/OUTPUT_FORMATS.md](docs/OUTPUT_FORMATS.md) | Output format details |
| [docs/API_REFERENCE.md](docs/API_REFERENCE.md) | Python API docs |
| [CHANGELOG.md](CHANGELOG.md) | Version history |
| [ROADMAP.md](ROADMAP.md) | Future plans |

### Contributing

| Document | Purpose |
|----------|---------|
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup |
| [TEST.md](TEST.md) | Testing guide |
| [docs/RELEASE.md](docs/RELEASE.md) | Release process |

**Documentation hub:** [docs/index.md](docs/index.md)

---

## Results Structure

```text
results/
├── individual-repos/      # Repository scans
├── individual-images/     # Container scans
├── individual-iac/        # IaC scans
├── individual-web/        # DAST scans
├── individual-gitlab/     # GitLab scans
├── individual-k8s/        # K8s scans
└── summaries/             # Unified reports
    ├── findings.json
    ├── SUMMARY.md
    ├── dashboard.html
    └── findings.sarif
```

---

## Severity Levels

| Level | Meaning | Action |
|-------|---------|--------|
| **CRITICAL** | Verified secrets, RCE | Fix immediately |
| **HIGH** | SQL injection, XSS | Fix within 1 week |
| **MEDIUM** | Weak crypto, misconfig | Fix within 1 month |
| **LOW** | Info disclosure | Fix when convenient |

---

## Compliance Frameworks

All findings auto-enriched with 6 frameworks:

- **OWASP Top 10 2021** - Web security categories
- **CWE Top 25 2024** - Common weakness types
- **NIST CSF 2.0** - Risk management
- **PCI DSS 4.0** - Payment security
- **CIS Controls v8.1** - Security best practices
- **MITRE ATT&CK** - Attack techniques

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Tools not found | `jmotools setup --check` |
| Permission denied | `chmod +x scripts/**/*.sh` |
| Docker issues | [docs/DOCKER_README.md#troubleshooting](docs/DOCKER_README.md#troubleshooting) |
| CI failures | [docs/CI_TROUBLESHOOTING.md](docs/CI_TROUBLESHOOTING.md) |

---

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and standards.

```bash
git clone https://github.com/jimmy058910/jmo-security-repo.git
cd jmo-security-repo
pip install -e .
make dev-deps
make pre-commit-install
make test
```

---

## Support

If this toolkit saves you time, consider supporting development:

- **Ko-fi:** <https://ko-fi.com/jmogaming>
- **GitHub Sponsors:** <https://github.com/sponsors/jimmy058910>

---

## License

Dual licensed under [MIT](LICENSE-MIT) OR [Apache 2.0](LICENSE-APACHE).

---

## Related Resources

- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - Verified secrets scanning
- [Semgrep](https://semgrep.dev) - Multi-language SAST
- [Trivy](https://aquasecurity.github.io/trivy/) - Vulnerability scanning
- [OWASP ZAP](https://www.zaproxy.org/) - DAST scanning

---

**Author:** James Moceri

**Project:** <https://jmotools.com> | [GitHub](https://github.com/jimmy058910/jmo-security-repo)
