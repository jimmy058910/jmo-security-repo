# JMO Security Suite — Documentation Hub

[![Tests](https://github.com/jimmy058910/jmo-security-repo/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/jimmy058910/jmo-security-repo/actions/workflows/tests.yml?query=branch%3Amain)
[![codecov](https://codecov.io/gh/jimmy058910/jmo-security-repo/branch/main/graph/badge.svg)](https://app.codecov.io/gh/jimmy058910/jmo-security-repo)

**Central navigation for all JMo Security documentation. Find what you need based on your role and experience level.**

---

## 🎉 Latest Updates (October 2025)

- 🧙 **Interactive Wizard** - Beginner-friendly guided scanning
- 🐳 **Docker Images** - Zero-installation security scanning (3 variants)
- 🔒 **XSS Patched** - HTML dashboard security hardened
- 🛡️ **OSV Scanner** - Open-source vulnerability detection
- 📊 **Enriched SARIF 2.1.0** - CWE/OWASP/CVE taxonomies
- ⚙️ **Type-Safe Severity** - Cleaner code with comparison operators
- 🎯 **88% Test Coverage** - 100/100 tests passing
- 📚 **Documentation Consolidation** - Streamlined structure

See [../CHANGELOG.md](../CHANGELOG.md) for complete details.

---

## 🚀 Getting Started (By User Type)

### Complete Beginner (Never Used Security Tools)

**Start Here:** [Docker Guide](DOCKER_README.md#quick-start-absolute-beginners) or run `jmotools wizard`

**Why:** Zero-installation path with step-by-step guidance. The wizard walks you through everything interactively.

**Next Steps:**

1. Run your first scan (wizard handles it)
2. Learn about results: [Understanding Results](#-understanding-results)
3. Explore wizard patterns: [Wizard Examples](examples/wizard-examples.md)

---

### Developer (Familiar with CLI)

**Start Here:** [Quick Start Guide](../QUICKSTART.md)

**Why:** Fast 5-minute setup with platform-specific instructions (Linux/WSL/macOS).

**Next Steps:**

1. Install and verify tools: [QUICKSTART — Step 1](../QUICKSTART.md#step-1-verify-environment)
2. Run your first scan: [QUICKSTART — Step 3](../QUICKSTART.md#step-3-run-the-security-audit)
3. Explore advanced features: [User Guide](USER_GUIDE.md)

---

### DevOps/SRE (CI/CD Integration Focus)

**Start Here:** [Docker Guide](DOCKER_README.md#cicd-integration)

**Why:** Container-based deployment, proven CI/CD patterns for GitHub Actions, GitLab CI, Jenkins.

**Next Steps:**

1. Review CI/CD examples: [GitHub Actions Docker Examples](examples/github-actions-docker.yml)
2. Configure severity gating: [Docker Guide — CI Gating](DOCKER_README.md#scan-with-ci-gating)
3. Set up SARIF uploads: [User Guide — SARIF](USER_GUIDE.md#sarif-and-html-dashboard)

---

### Advanced User (Fine-Tuning & Custom Profiles)

**Start Here:** [User Guide](USER_GUIDE.md)

**Why:** Comprehensive configuration reference, CLI synopsis, suppressions, advanced workflows.

**Next Steps:**

1. Create custom profiles: [User Guide — Configuration](USER_GUIDE.md#configuration-jmoyml)
2. Set up suppressions: [User Guide — Suppressions](USER_GUIDE.md#suppressions)
3. Optimize performance: [User Guide — Profiling](USER_GUIDE.md#profiling-and-performance)

---

### Contributor (Code Contributions)

**Start Here:** [Contributing Guide](../CONTRIBUTING.md)

**Why:** Dev setup, coding standards, PR workflow, testing requirements.

**Next Steps:**

1. Set up dev environment: [CONTRIBUTING — Dev Setup](../CONTRIBUTING.md#development-setup)
2. Understand testing: [Testing Guide](../TEST.md)
3. Learn release process: [Release Guide](RELEASE.md)

---

## 📚 Complete Documentation Index

### Core Documentation

| Document | Purpose | Audience |
|----------|---------|----------|
| [README.md](../README.md) | Project overview, "Three Ways to Get Started" | Everyone |
| [QUICKSTART.md](../QUICKSTART.md) | 5-minute universal guide | Developers |
| [USER_GUIDE.md](USER_GUIDE.md) | Comprehensive reference | Advanced users |
| [DOCKER_README.md](DOCKER_README.md) | Complete Docker guide (beginner → advanced) | All levels |

### Guides & Examples

| Document | Purpose | Audience |
|----------|---------|----------|
| [Wizard Examples](examples/wizard-examples.md) | Interactive wizard workflows | Beginners |
| [TSV Scanning](examples/scan_from_tsv.md) | Clone and scan from TSV files | DevOps |
| [GitHub Actions Docker](examples/github-actions-docker.yml) | CI/CD workflow examples | DevOps/SRE |
| [Examples Index](examples/README.md) | All examples overview | Everyone |

### Project Management

| Document | Purpose | Audience |
|----------|---------|----------|
| [CHANGELOG.md](../CHANGELOG.md) | Version history | Everyone |
| [ROADMAP.md](../ROADMAP.md) | Future plans & milestones | Everyone |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Contribution guidelines | Contributors |
| [TEST.md](../TEST.md) | Testing guide | Contributors |
| [RELEASE.md](RELEASE.md) | Release process | Maintainers |

### Technical References

| Document | Purpose | Audience |
|----------|---------|----------|
| [MCP Setup](MCP_SETUP.md) | MCP server integration | Advanced |
| [CommonFinding Schema](schemas/common_finding.v1.json) | Data schema spec | Developers |
| [Screenshots Guide](screenshots/README.md) | Screenshot capture | Contributors |
| [SAMPLE_OUTPUTS.md](../SAMPLE_OUTPUTS.md) | Example scan outputs | Everyone |

---

## 🔍 Understanding Results

### Severity Levels

| Level | Meaning | Action Required |
|-------|---------|-----------------|
| **CRITICAL** | Immediate security risk (hardcoded passwords, RCE) | Fix immediately |
| **HIGH** | Serious issue (SQL injection, XSS, high-severity CVEs) | Fix within 1 week |
| **MEDIUM** | Moderate risk (weak crypto, missing auth checks) | Fix within 1 month |
| **LOW** | Minor issue (info disclosure, weak headers) | Fix when convenient |
| **INFO** | Informational (deprecated APIs, style issues) | Optional improvement |

### Output Files

**After scanning, check these files in `results/summaries/`:**

- **`dashboard.html`** - Interactive web dashboard (recommended first view)
- **`SUMMARY.md`** - Human-readable text summary with top issues
- **`findings.json`** - Machine-readable normalized findings
- **`findings.sarif`** - SARIF 2.1.0 for GitHub/GitLab Security tabs
- **`findings.yaml`** - YAML format (requires PyYAML)
- **`SUPPRESSIONS.md`** - Suppressed findings summary (if suppressions used)
- **`timings.json`** - Performance profiling data (when `--profile` used)

---

## 🛠️ Common Tasks

### Quick Reference

**Run your first scan:**

```bash
# Wizard (easiest)
jmotools wizard

# Docker (zero tools)
docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results /scan/results --profile balanced --human-logs

# CLI (local tools)
jmotools balanced --repos-dir ~/repos
```

**View results:**

```bash
# Open dashboard
open results/summaries/dashboard.html  # macOS
xdg-open results/summaries/dashboard.html  # Linux

# Read summary
cat results/summaries/SUMMARY.md
```

**Common workflows:**

- [Fast pre-commit scan](examples/wizard-examples.md#quick-validation-before-commit)
- [CI/CD integration](DOCKER_README.md#cicd-integration)
- [Multi-repo audit](examples/scan_from_tsv.md)
- [Scheduled scans](../QUICKSTART.md#workflow-3-scheduled-weekly-audit)

---

## 🆘 Getting Help

### Documentation

- **General questions:** [README.md](../README.md) and [USER_GUIDE.md](USER_GUIDE.md)
- **Setup issues:** [QUICKSTART.md](../QUICKSTART.md) troubleshooting section
- **Docker problems:** [DOCKER_README.md — Troubleshooting](DOCKER_README.md#troubleshooting)
- **CI failures:** [User Guide — CI Troubleshooting](USER_GUIDE.md#interpreting-ci-failures-deeper-guide)

### Support Channels

- **Issues:** <https://github.com/jimmy058910/jmo-security-repo/issues>
- **Discussions:** <https://github.com/jimmy058910/jmo-security-repo/discussions>
- **Email:** <general@jmogaming.com>
- **Website:** <https://jmotools.com>

### Support the Project

- **Ko-fi:** <https://ko-fi.com/jmogaming>
- **Star on GitHub:** <https://github.com/jimmy058910/jmo-security-repo>
- **Contribute:** [CONTRIBUTING.md](../CONTRIBUTING.md)

## What's in this toolkit

- Orchestrates secrets (gitleaks, noseyparker, trufflehog), SAST (Semgrep, Bandit), SBOM+vulnerabilities (Syft, Trivy, OSV), IaC (Checkov, tfsec), and Dockerfile (Hadolint) scanners via a unified CLI
- Normalizes outputs into a CommonFinding schema (v1.0.0) for consistent reporting with stable fingerprinting
- Ships human-friendly HTML dashboard (XSS-secured) and machine-friendly JSON/YAML/SARIF 2.1.0 (enriched with taxonomies)
- Supports profiles, per-tool flags/timeouts, retries, include/exclude patterns, and fine-grained suppression
- Type-safe severity enum (CRITICAL > HIGH > MEDIUM > LOW > INFO) with comparison operators

## Start here

1. Verify environment

```bash
make verify-env
```

1. Run a quick scan

```bash
jmo ci --repos-dir ~/repos --profile-name fast --fail-on HIGH --profile --human-logs
```

1. Open the dashboard (results/summaries/dashboard.html)

- Learn more about features and profiling: [User Guide — SARIF and HTML dashboard](USER_GUIDE.md#sarif-and-html-dashboard)

Note: CI runs on ubuntu-latest and macos-latest across Python 3.10, 3.11, and 3.12, with concurrency and job timeouts to keep runs fast and reliable.

## WSL quick install checklist

If you're on Windows Subsystem for Linux (WSL), this gets you to green fast:

- Use WSL2 with Ubuntu 20.04+ (22.04+ recommended)
- Update core packages: `sudo apt-get update -y && sudo apt-get install -y build-essential git jq python3 python3-pip`
- Verify environment and get tool hints: `make verify-env`
- Optional curated tools install/upgrade: `make tools` and `make tools-upgrade`
- Nosey Parker (native, recommended on WSL): see [User Guide — Nosey Parker on WSL](USER_GUIDE.md#nosey-parker-on-wsl-native-recommended-and-auto-fallback-docker)
- Ensure `~/.local/bin` is on PATH (for user-local tools): `echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc`

## Key docs

- Configuration reference: see [USER_GUIDE.md](USER_GUIDE.md#configuration-jmoyml)
- Suppressions: see [USER_GUIDE.md](USER_GUIDE.md#suppressions)
- CLI synopsis: see [USER_GUIDE.md](USER_GUIDE.md#reference-cli-synopsis)

## Contributing and releases

- Tests: [../TEST.md](../TEST.md)
- Changelog: [../CHANGELOG.md](../CHANGELOG.md)
- License: [../LICENSE](../LICENSE)

## FAQ

Q: Tools not found or partial toolchain installed?

- A: Run `make verify-env` for OS-aware hints. You can also run with `--allow-missing-tools` to generate empty stubs and still exercise the pipeline.

Q: No repositories detected when using `--repos-dir`?

- A: Only immediate subfolders are considered repos. Ensure each contains a `.git` folder or pass `--repo` for a single path, or `--targets` file.

Q: YAML output missing?

- A: Install `pyyaml` to enable the YAML reporter. Otherwise JSON/MD/HTML still work; see [User Guide — Troubleshooting](USER_GUIDE.md#troubleshooting).

Q: Scans are slow on large directories?

- A: Use the `fast` profile, increase `threads`, and consult `timings.json` by running `jmo report --profile`. See [User Guide — Configuration](USER_GUIDE.md#configuration-jmoyml).

Q: How do I suppress false positives?

- A: Create a `jmo.suppress.yml` as described in [User Guide — Suppressions](USER_GUIDE.md#suppressions). A summary is written to `SUPPRESSIONS.md` during report/ci.
