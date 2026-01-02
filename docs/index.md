# JMo Security Documentation

[![Tests](https://github.com/jimmy058910/jmo-security-repo/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/jimmy058910/jmo-security-repo/actions/workflows/ci.yml?query=branch%3Amain)
[![codecov](https://codecov.io/gh/jimmy058910/jmo-security-repo/branch/main/graph/badge.svg)](https://app.codecov.io/gh/jimmy058910/jmo-security-repo)
[![PyPI version](https://badge.fury.io/py/jmo-security.svg)](https://badge.fury.io/py/jmo-security)
[![Docker Pulls](https://img.shields.io/docker/pulls/jmogaming/jmo-security)](https://hub.docker.com/r/jmogaming/jmo-security)

**Central navigation for all JMo Security documentation.**

---

## Start Here

| I am a... | Start with... |
|-----------|---------------|
| **Complete beginner** | [Docker Quick Start](DOCKER_README.md#quick-start-absolute-beginners) |
| **Developer** | [Quick Start Guide](../QUICKSTART.md) |
| **DevOps/SRE** | [CI/CD Integration](DOCKER_README.md#cicd-integration) |
| **Advanced user** | [User Guide](USER_GUIDE.md) |
| **Contributor** | [Contributing Guide](../CONTRIBUTING.md) |

---

## Quick Lookup

| I want to... | Go to... |
|--------------|----------|
| Install JMo Security | [Quick Start](../QUICKSTART.md) |
| Use Docker | [Docker Guide](DOCKER_README.md) |
| Install/update security tools | [User Guide: Tool Management](USER_GUIDE.md#tool-management) |
| Configure scanning | [User Guide: Configuration](USER_GUIDE.md#configuration-jmoyml) |
| Speed up scans | [Scan Optimization](SCAN_OPTIMIZATION.md) |
| Set up CI/CD | [Docker Guide: CI/CD](DOCKER_README.md#cicd-integration) |
| Suppress false positives | [User Guide: Suppressions](USER_GUIDE.md#suppressions) |
| Compare scans (diff) | [Diff Guide](DIFF_GUIDE.md) |
| Track trends over time | [Trends Guide](TRENDS_GUIDE.md) |
| View scan history | [History Guide](HISTORY_GUIDE.md) |
| SLSA attestation | [SLSA Guide](SLSA_GUIDE.md) |
| Understand results | [Results Guide](RESULTS_GUIDE.md) |
| Use policy-as-code | [Policy-as-Code Guide](POLICY_AS_CODE.md) |
| Set up AI remediation | [MCP Setup](MCP_SETUP.md) |
| Schedule automated scans | [Schedule Guide](SCHEDULE_GUIDE.md) |
| Troubleshoot CI failures | [CI Troubleshooting](../CONTRIBUTING.md#ci-troubleshooting) |

---

## Documentation Index

### Getting Started

| Document | Purpose |
|----------|---------|
| [README](../README.md) | Project overview |
| [Quick Start](../QUICKSTART.md) | 5-minute installation guide |
| [Docker Guide](DOCKER_README.md) | Docker installation, variants, CI/CD |
| [Installation Guide](MANUAL_INSTALLATION.md) | Platform-specific installation (macOS, Windows, WSL, Linux) |

### Reference

| Document | Purpose |
|----------|---------|
| [User Guide](USER_GUIDE.md) | Comprehensive reference (CLI, configuration, features) |
| [Profiles and Tools](PROFILES_AND_TOOLS.md) | Canonical tool lists by profile, dependencies |
| [Scan Optimization](SCAN_OPTIMIZATION.md) | Speed optimization strategies (threads, caching, tool config) |
| [Command Reference](QUICK_REFERENCE.md) | Quick command cheat sheet |
| [API Reference](API_REFERENCE.md) | Python API documentation |

### Results and Reporting

| Document | Purpose |
|----------|---------|
| [Results Guide](RESULTS_GUIDE.md) | Understanding findings, output formats, triage workflow |
| [Sample Outputs](../SAMPLE_OUTPUTS.md) | Example scan outputs |

### Features

| Document | Purpose |
|----------|---------|
| [Policy-as-Code](POLICY_AS_CODE.md) | OPA-based security policies |
| [Schedule Guide](SCHEDULE_GUIDE.md) | Automated scan scheduling |
| [Telemetry](TELEMETRY.md) | Privacy-first usage analytics |

### Advanced Features

| Document | Purpose |
|----------|---------|
| [History Guide](HISTORY_GUIDE.md) | SQLite storage for scan persistence and querying |
| [Trends Guide](TRENDS_GUIDE.md) | Statistical trend analysis (Mann-Kendall, scoring) |
| [Diff Guide](DIFF_GUIDE.md) | Machine-readable diffs for CI/CD, PR comments |
| [SLSA Guide](SLSA_GUIDE.md) | SLSA attestation, Sigstore signing, tamper detection |

### AI Integration

| Document | Purpose |
|----------|---------|
| [MCP Setup](MCP_SETUP.md) | MCP server setup (includes quick reference) |
| [GitHub Copilot](integrations/GITHUB_COPILOT.md) | VS Code Copilot integration |
| [Claude Code](integrations/CLAUDE_CODE.md) | Claude Code CLI integration |

### Examples

| Document | Purpose |
|----------|---------|
| [Examples Index](examples/README.md) | All examples overview |
| [Wizard Examples](examples/wizard-examples.md) | Interactive wizard workflows |
| [Diff Workflows](examples/diff-workflows.md) | Scan comparison patterns |
| [CI/CD Trends](examples/ci-cd-trends.md) | Trend analysis in CI/CD |
| [Attestation Workflows](examples/attestation-workflows.md) | SLSA attestation patterns |
| [Policy Workflows](examples/policy-workflows.md) | Policy enforcement in CI/CD |
| [Slack Notifications](examples/slack-notifications.md) | Slack integration patterns |

### Operations

| Document | Purpose |
|----------|---------|
| [CI Troubleshooting](../CONTRIBUTING.md#ci-troubleshooting) | Debugging CI failures |
| [Release Process](RELEASE.md) | Release workflow, WSL/macOS validation |
| [Version Management](VERSION_MANAGEMENT.md) | Tool version system |

### Contributing

| Document | Purpose |
|----------|---------|
| [Contributing](../CONTRIBUTING.md) | Development setup, git workflow, standards |
| [Testing Guide](../TEST.md) | Test suite documentation |
| [Dependency Management](DEPENDENCY_MANAGEMENT.md) | Managing dependencies |

### Project

| Document | Purpose |
|----------|---------|
| [Changelog](../CHANGELOG.md) | Version history |
| [Roadmap](../ROADMAP.md) | Future plans |
| [Contributors](../CONTRIBUTORS.md) | Community contributors |

---

## Tools Overview

JMo Security orchestrates 28 security scanners across 11 categories:

| Category | Tools |
|----------|-------|
| Secrets | TruffleHog, Nosey Parker, Semgrep-Secrets |
| SAST | Semgrep, Bandit, Gosec, Horusec |
| SBOM | Syft, CDXgen, ScanCode |
| SCA | Trivy, Grype, OSV-Scanner, Dependency-Check |
| IaC | Checkov, Checkov-CICD |
| Cloud/CSPM | Prowler, Kubescape |
| DAST | OWASP ZAP, Nuclei |
| Dockerfile | Hadolint |
| Malware | YARA |
| System | Lynis |
| Runtime | Trivy-RBAC, Falco, AFL++ |

**Tool details:** [Profiles and Tools Reference](PROFILES_AND_TOOLS.md) | [User Guide: Tool Overview](USER_GUIDE.md#tool-overview)

---

## Getting Help

### Documentation

- **Installation issues:** [Quick Start](../QUICKSTART.md) or [Installation Guide](MANUAL_INSTALLATION.md)
- **Docker problems:** [Docker Guide: Troubleshooting](DOCKER_README.md#troubleshooting)
- **CI failures:** [CI Troubleshooting](../CONTRIBUTING.md#ci-troubleshooting)
- **General questions:** [User Guide](USER_GUIDE.md)

### Support Channels

- **Issues:** <https://github.com/jimmy058910/jmo-security-repo/issues>
- **Discussions:** <https://github.com/jimmy058910/jmo-security-repo/discussions>
- **Website:** <https://jmotools.com>

### Support the Project

- **Ko-fi:** <https://ko-fi.com/jmogaming>
- **GitHub Sponsors:** <https://github.com/sponsors/jimmy058910>
- **Star on GitHub:** <https://github.com/jimmy058910/jmo-security-repo>

---

**Last Updated:** December 2025
