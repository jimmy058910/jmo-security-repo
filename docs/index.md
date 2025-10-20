# JMO Security Suite — Documentation Hub

[![Tests](https://github.com/jimmy058910/jmo-security-repo/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/jimmy058910/jmo-security-repo/actions/workflows/tests.yml?query=branch%3Amain)
[![codecov](https://codecov.io/gh/jimmy058910/jmo-security-repo/branch/main/graph/badge.svg)](https://app.codecov.io/gh/jimmy058910/jmo-security-repo)

**Central navigation for all JMo Security documentation. Find what you need based on your role and experience level.**

---

## 🎉 Latest Updates (October 2025)

- 🧙 **Interactive Wizard (v0.6.2)** - Now supports 6 target types: repos, images, IaC, URLs, GitLab, K8s
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
| [Version Management](VERSION_MANAGEMENT.md) | 5-layer version system | Maintainers |
| [Compliance Framework Analysis](COMPLIANCE_FRAMEWORK_ANALYSIS.md) | Framework mappings detail | Advanced |
| [Context7 Usage](CONTEXT7_USAGE.md) | MCP Context7 integration | Advanced |
| [Telemetry](TELEMETRY.md) | Privacy-first usage tracking (v0.7.0+) | Everyone |
| [Testing Matrix](TESTING_MATRIX.md) | Test coverage dimensions | Contributors |
| [Usage Matrix](USAGE_MATRIX.md) | Use case configurations | Everyone |

> **Note:** Infrastructure and business documentation (CAPTCHA setup, email telemetry, newsletter templates) is maintained separately in `dev-only/` (gitignored). These are maintainer-only resources not needed for general development or usage.

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

- Orchestrates secrets (TruffleHog verified, Nosey Parker), SAST (Semgrep, Bandit), SBOM+vulnerabilities (Syft, Trivy), IaC (Checkov), Dockerfile (Hadolint), DAST (OWASP ZAP), runtime security (Falco), and fuzzing (AFL++) scanners via a unified CLI
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

## 🪟 Windows Users Quick Start

**Windows has three options - choose based on your skill level:**

### ✅ Recommended: Docker Desktop OR WSL 2

Both options provide full 11+ tool support. Native Windows only supports 6 tools (55% coverage).

**Docker Desktop (Easiest - 5 minutes):**

- Download: <https://www.docker.com/products/docker-desktop>
- Pull image: `docker pull ghcr.io/jimmy058910/jmo-security:latest`
- Run scan (PowerShell): `docker run --rm -v "${PWD}:/scan" ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan --results /scan/results --profile balanced --human-logs`
- View results: `start results\summaries\dashboard.html`
- **Key Windows syntax:** Use `${PWD}` (with curly braces) and quotes

**WSL 2 (Best Performance - 15 minutes):**

1. Install WSL 2 (PowerShell as Admin): `wsl --install`
2. Restart, then launch Ubuntu from Start Menu
3. Update packages: `sudo apt-get update -y && sudo apt-get upgrade -y`
4. Install dependencies: `sudo apt-get install -y build-essential git jq python3 python3-pip curl wget`
5. Install JMo: `pip install jmo-security`
6. Add to PATH: `echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc`
7. Auto-install tools: `git clone https://github.com/jimmy058910/jmo-security-repo.git && cd jmo-security-repo && make tools`
8. Run scan: `jmotools balanced --repos-dir ~/projects`
9. View results: `explorer.exe results/summaries/dashboard.html`

**Performance tip:** Use WSL filesystem (`~` paths) instead of Windows filesystem (`/mnt/c/`) for 2-3x faster scans.

**⚠️ Native Windows (NOT recommended):**

- Only 6 out of 11+ tools work (55% coverage)
- Missing DAST (ZAP), runtime security (Falco), fuzzing (AFL++), Hadolint, Nosey Parker
- You will miss 20-30% of vulnerabilities
- Only use if Docker/WSL prohibited by organization

📖 **Full Windows guide:** [QUICKSTART.md — Windows Users](../QUICKSTART.md#-windows-users-start-here)

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

## Why These Tools? (v0.5.0 Tool Selection Rationale)

### Why TruffleHog over Gitleaks?

**Decision:** Removed Gitleaks, kept TruffleHog as primary secrets scanner

**Rationale:**

- **Verification Advantage:** TruffleHog actively verifies secrets against 800+ service APIs, eliminating **95% of false positives**
- **Precision:** 74% precision (TruffleHog) vs 46% precision (Gitleaks) in academic benchmarks
- **Platform Coverage:** TruffleHog scans Git repos, Docker images, S3 buckets, Slack, and 17+ platforms; Gitleaks is code-only
- **Actionable Results:** `--only-verified` flag provides verified credentials that actually authenticate, not just pattern matches
- **False Positive Reduction:** 70-80% reduction in triage time compared to pattern-only scanners

**Use Case:** Run TruffleHog with `--only-verified` in CI/CD for zero-false-positive secrets detection

---

### Why Remove TFSec?

**Decision:** Removed TFSec completely, consolidated to Trivy

**Rationale:**

- **Deprecated:** TFSec acquired by Aqua Security in July 2021, fully merged into Trivy
- **Official Statement:** TFSec GitHub repository explicitly states "tfsec is now part of Trivy"
- **Zero New Development:** TFSec is in maintenance mode with zero new features
- **100% Redundant:** Trivy inherited TFSec's entire Terraform scanning engine (154 policies)
- **Superior Coverage:** Trivy provides **322 total IaC policies** (vs TFSec's 154) plus container scanning, vulnerability detection, and SBOM generation

**Migration:** All TFSec functionality available in Trivy's IaC scanning mode

---

### Why Remove OSV-Scanner?

**Decision:** Removed OSV-Scanner, kept Trivy as primary vulnerability scanner

**Rationale:**

- **Container Limitation:** OSV-Scanner's documented weakness in scanning containerized applications is a showstopper for modern DevSecOps
- **Vendor-Aware Detection:** Trivy handles backported fixes correctly (e.g., Red Hat patches CVEs in older package versions without version number changes)
- **Layer-Aware Scanning:** Trivy identifies which container layer introduced vulnerabilities, OSV-Scanner cannot
- **OS Package Coverage:** Trivy provides superior OS package vulnerability coverage with vendor-specific advisories (RHEL, Debian, Ubuntu)
- **42Analytics Testing:** OSV-Scanner misses vulnerabilities in language-specific libraries installed within Docker images

**Use Case:** Trivy for container-based workflows, OSV-Scanner optional only for pure source code scanning

---

### Why Keep Nosey Parker (Deep Profile Only)?

**Decision:** Kept Nosey Parker in deep profile despite tool consolidation goals

**Rationale:**

- **Best-in-Class Precision:** 98.5% precision (best of all secrets scanners per Praetorian testing)
- **ML-Powered Denoising:** Finds secrets TruffleHog misses (266 vs 197 true positives in research)
- **Complementary Coverage:** ML approach catches patterns verification-based scanners miss
- **Deep Profile Philosophy:** Accept longer scan times for maximum coverage in comprehensive audits
- **Use Case:** Historical repository audits, compliance scans, security audits requiring exhaustive coverage

**Trade-off:** Slightly higher tool count in deep profile for significantly better coverage

---

### Why Keep Bandit (Deep Profile Only)?

**Decision:** Kept Bandit in deep profile for Python-specific edge cases

**Rationale:**

- **Unique Findings:** Real-world Zulip testing showed 10% of findings unique to Bandit
- **68 Refined Checks:** Python-specific checks refined over years from OpenStack Security Project
- **Confidence Ratings:** Provides both confidence and severity ratings (Semgrep only has severity)
- **Edge Case Coverage:** Detects patterns Semgrep misses (e.g., Django `QuerySet.extra()` usage, capitalized environment variables)
- **Deep Profile Philosophy:** Maximize coverage, not minimize tool count

**Alternative:** Organizations can consolidate to Semgrep Pro for multi-language SAST, accepting 5-10% edge case detection loss

---

### Why Add OWASP ZAP (DAST)?

**Decision:** Added OWASP ZAP to balanced + deep profiles

**Rationale:**

- **Critical Gap:** Static analysis (SAST) misses environment-specific issues and runtime vulnerabilities
- **20-30% More Vulnerabilities:** DAST finds an average of 20-30% more vulnerabilities than SAST alone (industry research)
- **Runtime Testing:** Detects authentication bypass, session hijacking, business logic flaws, production misconfigurations
- **API Coverage:** 83% of web traffic is APIs, ZAP provides REST API and GraphQL testing
- **Free + Mature:** 12,000+ GitHub stars, Apache 2.0 license, active community

**Use Case:** Run ZAP in test environments during build stage (15-30 min)

---

### Why Add Falco (Runtime Security)?

**Decision:** Added Falco to deep profile for container/Kubernetes security

**Rationale:**

- **Zero-Day Detection:** Static scanning (Trivy) only catches known vulnerabilities; runtime security detects zero-day exploits
- **eBPF-Based Monitoring:** Kernel-level visibility without overhead
- **Container Escapes:** Detects container escape attempts, privilege escalation, unauthorized file access
- **CNCF Graduated:** Industry-standard runtime security for Kubernetes (used by major enterprises)
- **Policy Violations:** Real-time detection of policy violations during execution

**Use Case:** Continuous monitoring in production Kubernetes environments

---

### Why Add AFL++ (Fuzzing)?

**Decision:** Added AFL++ to deep profile for coverage-guided fuzzing

**Rationale:**

- **Unknown Vulnerabilities:** Fuzzing discovers bugs that traditional testing misses (not pattern-matching)
- **10,000+ Bugs Found:** Google's OSS-Fuzz has found 10,000+ bugs in critical open-source projects using AFL-based fuzzing
- **Coverage-Guided:** Mutates inputs to maximize code path exploration (smarter than random fuzzing)
- **Proven Track Record:** Most advanced fork of American Fuzzy Lop with feedback-based mutation engine

**Use Case:** Nightly fuzzing runs on 3-5 critical components (parsers, input handlers, cryptographic functions)

---

### Why Trivy as Multi-Purpose Champion?

**Decision:** Trivy is the core of all three profiles

**Rationale:**

- **Multi-Purpose:** Vulnerabilities, container security, IaC scanning, secrets detection (secondary), SBOM generation
- **Lightning Fast:** Scans complete in seconds (critical for CI/CD)
- **Inherited TFSec:** Complete Terraform scanning engine from deprecated TFSec
- **Container-Native:** Layer-aware scanning, vendor-aware detection, Docker/OCI image support
- **Low False Positives:** Conservative secrets scanning, backport-aware vulnerability detection

**Use Case:** Run Trivy in all profiles for speed + breadth of coverage

---

### Profile Philosophy

**Fast (3 tools):** Best-in-breed tools for each major category (secrets, SAST, SCA/container/IaC)

- Use Case: Pre-commit checks, quick validation, CI/CD gates (5-8 minutes)

**Balanced (7 tools):** Production-ready comprehensive coverage with DAST

- Use Case: CI/CD pipelines, regular audits, production scans (15-20 minutes)

**Deep (11 tools):** Maximum coverage accepting tool overhead for exhaustive detection

- Use Case: Security audits, compliance scans, pre-release validation (30-60 minutes)

---

### Industry Validation

**Survey Data (2024-2025):**

- 74% of organizations want toolchain consolidation (GitLab Global DevSecOps Survey)
- Best-in-class teams use 6-8 tools orchestrated through ASPM platforms
- Organizations with 11+ tools report highest false positive rates

**OWASP DevSecOps Maturity Model:**

- Level 2 (Walk): 5-7 tools (our balanced profile)
- Level 3 (Run): 6-8 tools orchestrated (our approach)

**Key Principle:** One excellent tool beats three mediocre tools. Prioritize developer experience and low false positives over tool count.

---
