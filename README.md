# JMo's Security Audit Tool Suite

<p align="center">
   <img src="assets/jmo-logo.png" alt="JMo Security Audit Tool Suite" width="220" />
</p>

[![Tests](https://github.com/jimmy058910/jmo-security-repo/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/jimmy058910/jmo-security-repo/actions/workflows/ci.yml?query=branch%3Amain)
[![codecov](https://codecov.io/gh/jimmy058910/jmo-security-repo/branch/main/graph/badge.svg)](https://app.codecov.io/gh/jimmy058910/jmo-security-repo)
[![PyPI version](https://badge.fury.io/py/jmo-security.svg)](https://badge.fury.io/py/jmo-security)
[![Python Versions](https://img.shields.io/pypi/pyversions/jmo-security.svg)](https://pypi.org/project/jmo-security/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker Pulls](https://img.shields.io/docker/pulls/jimmy058910/jmo-security)](https://hub.docker.com/r/jimmy058910/jmo-security)
[![GitHub Stars](https://img.shields.io/github/stars/jimmy058910/jmo-security-repo?style=social)](https://github.com/jimmy058910/jmo-security-repo)
[![Documentation](https://img.shields.io/badge/docs-ReadTheDocs-blue.svg)](https://docs.jmotools.com)
[![Blog](https://img.shields.io/badge/blog-Hashnode-2962FF.svg)](https://blog.jmotools.com)

## 📬 Stay Updated & Support

[![Newsletter](https://img.shields.io/badge/📧_Newsletter-Subscribe-667eea)](https://jmotools.com/subscribe.html)
[![Ko-fi](https://img.shields.io/badge/💚_Ko--fi-Support-ff5e5b?logo=ko-fi&logoColor=white)](https://ko-fi.com/jmogaming)
[![GitHub Sponsors](https://img.shields.io/badge/💰_Sponsor-GitHub-ea4aaa?logo=github&logoColor=white)](https://github.com/sponsors/jimmy058910)

**Get security tips and updates delivered to your inbox:**

- 🚀 New feature announcements
- 💡 Real-world security case studies & exclusive guides

**[Subscribe to Newsletter](https://jmotools.com/subscribe.html)** | **[Support Full-Time Development](https://ko-fi.com/jmogaming)**

---

<!-- CI/coverage/package badges (enable once configured)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-coming--soon-lightgrey)](#)
<!-- If/when a workflow exists, switch to:
[![Tests](https://github.com/jimmy058910/jmo-security-repo/actions/workflows/tests.yml/badge.svg)](https://github.com/jimmy058910/jmo-security-repo/actions/workflows/tests.yml)
-->
<!-- Codecov (enable after uploading coverage):
[![codecov](https://codecov.io/gh/jimmy058910/jmo-security-repo/branch/main/graph/badge.svg)](https://codecov.io/gh/jimmy058910/jmo-security-repo)
-->
<!-- PyPI (enable after first release):
[![PyPI - Version](https://img.shields.io/pypi/v/jmo-security)](https://pypi.org/project/jmo-security/)
-->

A terminal-first, cross-platform security audit toolkit that orchestrates multiple scanners (secrets, SAST, SBOM, IaC, Dockerfile) with a unified Python CLI, normalized outputs, and an HTML dashboard.

👉 New here? Read the comprehensive User Guide: [docs/USER_GUIDE.md](docs/USER_GUIDE.md)
Docs hub: [docs/index.md](docs/index.md)
Project homepage: [jmotools.com](https://jmotools.com)

> Origin story: This started as part of a Cybersecurity Capstone Project. It has since grown into a general-purpose toolkit. I’d love for folks with deeper expertise to jump in—issues and PRs are welcome!

Thinking about contributing? See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and coding standards. For publishing, see [docs/RELEASE.md](docs/RELEASE.md).

Roadmap & history:

- **Latest:** ROADMAP #2 (Interactive Wizard) ✅ Complete - see [docs/examples/wizard-examples.md](docs/examples/wizard-examples.md)
- Completed steps (summary): see [CHANGELOG.md](CHANGELOG.md) → ROADMAP Items #1-2 and Steps 1–13
- Active/planned work: see [ROADMAP.md](ROADMAP.md)

For scanning a list of repos from a TSV end-to-end (clone + unshallow + full toolchain), see: [docs/examples/scan_from_tsv.md](docs/examples/scan_from_tsv.md)

## ✅ CI and release at a glance

- Tests run on a matrix of operating systems and Python versions:
  - OS: ubuntu-latest, macos-latest
  - Python: 3.10, 3.11, 3.12
- CI uses concurrency to cancel redundant runs on rapid pushes and sets a 20-minute job timeout.
- Coverage is uploaded to Codecov without a token (OIDC/tokenless on public repos) using `codecov/codecov-action@v5`.
- Releases to PyPI use Trusted Publishers (OIDC) via `pypa/gh-action-pypi-publish@v1`; no PyPI API token is required once the repo is authorized in PyPI.

See `.github/workflows/tests.yml` and `.github/workflows/release.yml` for details.

Quick link: CI Troubleshooting → [Interpreting CI failures](docs/USER_GUIDE.md#interpreting-ci-failures-deeper-guide)

## 🎉 Recent Improvements

### v0.7.0 - Performance & UX (October 2025)

**Smart Defaults & Real-Time Feedback:**

- ✅ **Auto-Detect CPU Threads** - Automatically uses 75% of CPU cores for optimal performance (min 2, max 16)
  - No more guessing thread counts
  - Docker scans now utilize full CPU capacity
  - Override with `threads: auto` in jmo.yml or `JMO_THREADS=auto`
- ✅ **Real-Time Progress Tracking** - Live updates during long-running scans
  - Format: `[3/10] ✓ repo: my-app (45s) | Progress: 30% | ETA: 2m 15s`
  - Per-target timing shows which targets are slow
  - No more wondering if scan is frozen

**Why This Matters:**

- 🚀 **Faster Scans** - Proper CPU utilization reduces scan times by 40-60%
- 👀 **Better Visibility** - Know exactly what's happening during long scans (15-60 min)
- 🎯 **Smarter Defaults** - Works out-of-the-box without manual configuration

### v0.6.0 - Multi-Target Scanning (October 2025)

**BREAKTHROUGH: Unified Security Platform (ROADMAP #4 - Phase 1):**

Scan repositories AND infrastructure in one unified workflow!

- ✅ **Container Image Scanning** - Scan Docker/OCI images with Trivy + Syft for vulnerabilities, secrets, and SBOMs
- ✅ **IaC File Scanning** - Scan Terraform/CloudFormation/K8s manifests with Checkov + Trivy
- ✅ **Live Web URL Scanning** - DAST scanning of web apps and APIs with OWASP ZAP
- ✅ **GitLab Integration** - Scan GitLab repos with TruffleHog verified secrets detection
- ✅ **Kubernetes Cluster Scanning** - Live K8s cluster scanning with Trivy for vulnerabilities and misconfigurations
- ✅ **Unified Results** - All targets aggregated, deduplicated, and reported in one dashboard
- ✅ **Multi-Target CI/CD** - Scan multiple target types in one pipeline run

**Key Benefits:**

- 🎯 **Single Tool** - Replace 5+ separate security tools with one unified CLI
- 🚀 **Parallel Execution** - Scan images/IaC/URLs/repos simultaneously for faster results
- 📊 **Unified Reporting** - One dashboard for all findings across all targets
- 🔁 **CI/CD Ready** - Multi-target scanning with severity gating in one command
- 🔧 **Flexible** - Scan single targets or batch process from files

**Example: Complete Security Audit in One Command:**

```bash
# Scan repo + container image + live web app + K8s cluster together
jmo scan \
  --repo ./myapp \
  --image myapp:latest \
  --url https://myapp.com \
  --k8s-context prod \
  --results-dir ./audit-results
```

See [docs/USER_GUIDE.md — Multi-Target Scanning](docs/USER_GUIDE.md#multi-target-scanning-v060) for complete documentation.

---

### v0.5.0 - Tool Suite Consolidation (October 2025)

**Tool Suite Consolidation (ROADMAP #3):**

- ✅ **DAST coverage added** with OWASP ZAP (20-30% more vulnerabilities detected)
- ✅ **Runtime security monitoring** with Falco (zero-day exploit detection for containers/K8s)
- ✅ **Fuzzing capabilities** with AFL++ (coverage-guided vulnerability discovery)
- ✅ **Verified secrets** with TruffleHog (95% false positive reduction)
- ✅ **Removed deprecated tools** (gitleaks, tfsec, osv-scanner)
- ✅ **Profile restructuring** - Fast: 3 tools, Balanced: 7 tools, Deep: 11 tools

**Security & Bug Fixes (Phase 1 - October 2025):**

- ✅ **XSS vulnerability patched** in HTML dashboard with comprehensive input escaping
- ✅ **OSV scanner fully integrated** for open-source vulnerability detection
- ✅ **Type-safe severity enum** with comparison operators for cleaner code
- ✅ **Backward-compatible suppression keys** (`suppressions` and legacy `suppress`)

**Enhanced Features:**

- 🚀 **Enriched SARIF output** with CWE/OWASP/CVE taxonomies, code snippets, and CVSS scores
- ⚙️ **Configurable thread recommendations** via `jmo.yml` profiling section
- 📝 **Magic numbers extracted** to named constants for better maintainability
- 📚 **9 new roadmap enhancements** including Policy-as-Code (OPA), SLSA attestation, GitHub App, and more

**Quality Metrics:**

- ✅ 272/272 tests passing
- ✅ 91% code coverage (exceeds 85% requirement)
- ✅ No breaking changes to existing workflows

See [CHANGELOG.md](CHANGELOG.md) for complete details.

## 🚀 Three Ways to Get Started

> **🪟 Windows Users:** Use **Option 2 (Docker)** for the best experience. WSL2 with Docker Desktop provides zero-installation scanning with full tool compatibility. Native Windows support is limited due to tool availability. See [Docker for Windows Setup](#windows-docker-setup) below.

### Option 1: 🧙 Interactive Wizard (Recommended for Beginners)

**Never used security scanners before?** Start with the guided wizard:

**Prerequisites:**

- **Already installed?** Skip to running the wizard below
- **Need to install?** See [Installation Quick Reference](#-installation-quick-reference) (2 minutes)

**Run the wizard:**

```bash
jmotools wizard
```

**What the wizard provides:**

- ✅ **Step-by-step guidance** through all configuration options
- ✅ **Profile selection** (fast/balanced/deep) with time estimates
- ✅ **Docker vs native mode** - zero-installation Docker option!
- ✅ **Multi-target support (v0.6.2+)** - scan repos, images, IaC, URLs, GitLab, K8s
- ✅ **Smart detection** - auto-discovers repos, validates URLs/K8s contexts
- ✅ **Command preview** - see what will run before executing
- ✅ **Auto-open results** - dashboard and summary automatically displayed

**Non-interactive mode for automation:**

```bash
jmotools wizard --yes              # Use smart defaults
jmotools wizard --docker           # Force Docker mode
```

**Generate reusable artifacts:**

```bash
jmotools wizard --emit-make-target Makefile.security  # Team Makefile
jmotools wizard --emit-script scan.sh                 # Shell script
jmotools wizard --emit-gha .github/workflows/security.yml  # GitHub Actions
```

📖 **Full wizard guide:** [docs/examples/wizard-examples.md](docs/examples/wizard-examples.md)

---

### Option 2: 🐳 Docker (Zero Installation) ⭐ Recommended for Windows

**✨ Start scanning in 60 seconds with ZERO tool installation!**

Perfect for:

- 🪟 **Windows users** (WSL2 + Docker Desktop)
- 🚀 **Quick trials** (no commitment, no setup)
- 🔒 **CI/CD pipelines** (consistent environments)
- 🌍 **Any platform** (Linux, macOS, Windows)

```bash
# Pull the image (one-time, ~500MB)
docker pull ghcr.io/jimmy058910/jmo-security:latest

# Scan current directory
docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results /scan/results --profile balanced --human-logs

# View results
open results/summaries/dashboard.html  # macOS
xdg-open results/summaries/dashboard.html  # Linux
start results/summaries/dashboard.html  # Windows (WSL2)
```

**Three image variants available:**

- `latest` (~500MB) - All 12 scanners included
- `slim` (~200MB) - Core 6 scanners for CI/CD
- `alpine` (~150MB) - Minimal footprint

**Why Docker?**

- ✅ No Python/tool installation required
- ✅ Works identically on all platforms
- ✅ Automatic tool version management
- ✅ Isolated from your host system
- ✅ Perfect for Windows (native tools often unavailable)

📖 **Complete Docker guide:** [docs/DOCKER_README.md](docs/DOCKER_README.md)
📖 **Beginner Docker tutorial:** [docs/DOCKER_README.md#quick-start-absolute-beginners](docs/DOCKER_README.md#quick-start-absolute-beginners)

---

### Option 3: 🧪 CLI Wrapper Commands (Local Install)

**Prerequisites:**

- **Already have tools installed?** Skip to commands below
- **Need to install?** See [Installation Quick Reference](#-installation-quick-reference) (5-10 minutes)

**Quick wrapper commands:**

```bash
# Quick fast scan (auto-opens results)
jmotools fast --repos-dir ~/repos

# Balanced scan (recommended default)
jmotools balanced --repos-dir ~/repos

# Deep scan with all tools
jmotools full --repos-dir ~/repos
```

**Clone from TSV and scan:**

```bash
jmotools balanced --tsv ./repositories.tsv --dest ./cloned-repos
```

**Setup tools quickly:**

```bash
jmotools setup --check              # Verify tool installation
jmotools setup --auto-install       # Auto-install on Linux/WSL/macOS
```

**Makefile shortcuts:**

```bash
make setup             # Verify tools (installs package if needed)
make fast DIR=~/repos  # Run fast profile
make balanced DIR=~/repos
make full DIR=~/repos
```

Note: Under the hood, wrapper commands verify your OS/tools, optionally clone from TSV, run `jmo ci` with the appropriate profile, and auto-open results.

---

## 📦 Installation Quick Reference

**Choose your installation path based on experience level:**

### Path 1: Docker (Zero Installation - Recommended for Beginners)

**Time:** 2 minutes | **Tools:** All 11+ scanners included

```bash
# 1. Install Docker Desktop
# Download from: https://www.docker.com/products/docker-desktop
# (Windows/Mac/Linux all supported)

# 2. Pull JMo Security image (one-time, ~500MB)
docker pull ghcr.io/jimmy058910/jmo-security:latest

# 3. You're ready! No other installation needed.
# Run the wizard in Docker mode:
docker run -it --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest wizard
```

**✅ Best for:** Complete beginners, Windows users, quick trials, CI/CD

**📖 Full guide:** [Docker README](docs/DOCKER_README.md)

---

### Path 2: Python Package (pip install)

**Time:** 5-10 minutes | **Tools:** Install separately (see below)

```bash
# 1. Ensure Python 3.10+ installed
python3 --version  # Should be 3.10 or higher

# 2. Install JMo Security CLI
pip install jmo-security

# 3. Add to PATH (if needed)
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# 4. Verify installation
jmo --help
jmotools --help

# 5. Install security tools (choose one):

# Option A: Auto-install (Linux/WSL/macOS)
git clone https://github.com/jimmy058910/jmo-security-repo.git
cd jmo-security-repo
make tools        # Installs all tools
make verify-env   # Verify installation

# Option B: Manual install (see "Tool Installation" section below)
```

**✅ Best for:** Developers, advanced users, customization needs

**📖 Full guide:** [Quick Start Guide](QUICKSTART.md)

---

### Path 3: Clone Repository (Contributors)

**Time:** 10-15 minutes | **Tools:** Install separately

```bash
# 1. Clone repository
git clone https://github.com/jimmy058910/jmo-security-repo.git
cd jmo-security-repo

# 2. Install in editable mode
pip install -e .

# 3. Install dev dependencies
make dev-deps

# 4. Install pre-commit hooks
make pre-commit-install

# 5. Install security tools
make tools
make verify-env
```

**✅ Best for:** Contributors, development work

**📖 Full guide:** [Contributing Guide](CONTRIBUTING.md)

---

### Quick Decision Guide

| Your Situation | Recommended Path | Time |
|----------------|------------------|------|
| "I just want to scan something NOW" | Docker (Path 1) | 2 min |
| "I'm on Windows" | Docker (Path 1) or WSL 2 | 2-15 min |
| "I use security tools regularly" | pip install (Path 2) | 5-10 min |
| "I want to contribute code" | Clone repo (Path 3) | 10-15 min |
| "I'm a complete beginner" | Docker (Path 1) | 2 min |

**Still unsure?** → Use Docker (Path 1). You can always install locally later.

---

### Windows Docker Setup

**Recommended Setup for Windows Users:**

1. **Install WSL2** (Windows Subsystem for Linux 2)
   ```powershell
   # Run in PowerShell as Administrator
   wsl --install
   ```

2. **Install Docker Desktop for Windows**
   - Download: [https://www.docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop)
   - Enable WSL2 backend in Docker Desktop settings
   - Ensure "Use the WSL 2 based engine" is checked

3. **Run JMo Security in WSL2**
   ```bash
   # Open WSL2 terminal (Ubuntu)
   wsl

   # Pull JMo Security Docker image
   docker pull ghcr.io/jimmy058910/jmo-security:latest

   # Scan a repository
   docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest \
     scan --repo /scan --results /scan/results --profile balanced

   # View results (opens in Windows browser)
   explorer.exe results/summaries/dashboard.html
   ```

#### Alternative: Use the Wizard in Docker mode

```bash
# Clone this repo in WSL2
git clone https://github.com/jimmy058910/jmo-security-repo.git
cd jmo-security-repo

# Run wizard (auto-detects Docker)
pip install -e .
jmotools wizard --docker

# Follow the prompts - wizard handles everything!
```

**Why WSL2 + Docker?**

- ✅ **Best compatibility:** All 12 security tools work perfectly
- ✅ **Zero native Windows tools:** No Python/git/tool installation on Windows
- ✅ **Linux performance:** Scans run 2-3x faster than native Windows
- ✅ **Easy file access:** Access Windows files via `/mnt/c/Users/...`
- ✅ **Seamless integration:** Results open in Windows browser automatically

**Troubleshooting:**

- **Docker not found:** Ensure Docker Desktop is running and WSL2 integration is enabled
- **Slow scans:** Clone repos to WSL2 filesystem (`~/repos`), not Windows mount (`/mnt/c/`)
- **Permission denied:** Add your user to docker group: `sudo usermod -aG docker $USER`

📖 **Complete Windows guide:** [docs/DOCKER_README.md#windows-wsl2-setup](docs/DOCKER_README.md#windows-wsl2-setup)

---

## 🎯 Multi-Target Scanning Examples (v0.6.0+)

**New in v0.6.0:** Scan 6 different target types in one unified workflow!

### Quick Examples

**Scan a container image:**

```bash
jmo scan --image nginx:latest --results-dir ./image-scan
```

**Scan multiple images from file:**

```bash
# images.txt: one image per line
# nginx:latest
# postgres:15
# redis:alpine
jmo scan --images-file images.txt --results-dir ./registry-audit
```

**Scan Terraform state file:**

```bash
jmo scan --terraform-state terraform.tfstate --tools checkov trivy
```

**Scan live web application:**

```bash
jmo scan --url https://example.com --tools zap --results-dir ./web-audit
```

**Scan GitLab organization (all repos):**

```bash
jmo scan --gitlab-url https://gitlab.com --gitlab-token $GITLAB_TOKEN \
  --gitlab-group myorg --tools trufflehog
```

**Scan Kubernetes cluster:**

```bash
jmo scan --k8s-context prod --k8s-all-namespaces --tools trivy
```

**Multi-target audit (everything at once!):**

```bash
# Scan repository + container + web app + K8s in one command
jmo scan \
  --repo ./myapp \
  --image myapp:latest \
  --url https://myapp.com \
  --k8s-context prod \
  --k8s-namespace default \
  --results-dir ./complete-audit
```

**CI mode with multi-target scanning:**

```bash
# Scan + report + fail on HIGH severity in one command
jmo ci \
  --image myapp:latest \
  --url https://staging.myapp.com \
  --fail-on HIGH \
  --profile balanced
```

### Supported Target Types

| Target Type | Tools | CLI Arguments | Use Case |
|-------------|-------|---------------|----------|
| **Repositories** | trufflehog, semgrep, bandit, syft, trivy, checkov, hadolint | `--repo`, `--repos-dir`, `--targets` | Source code scanning |
| **Container Images** | trivy, syft | `--image`, `--images-file` | Registry audits, CI/CD gates |
| **IaC Files** | checkov, trivy | `--terraform-state`, `--cloudformation`, `--k8s-manifest` | Infrastructure compliance |
| **Web URLs** | zap | `--url`, `--urls-file`, `--api-spec` | DAST scanning |
| **GitLab Repos** | trufflehog | `--gitlab-repo`, `--gitlab-group`, `--gitlab-token` | GitLab security audits |
| **Kubernetes Clusters** | trivy | `--k8s-context`, `--k8s-namespace`, `--k8s-all-namespaces` | Live cluster audits |

**Results structure:**

```text
results/
├── individual-repos/        # Repository scans
├── individual-images/       # Container image scans
├── individual-iac/          # IaC file scans
├── individual-web/          # Web app/API scans
├── individual-gitlab/       # GitLab repo scans
├── individual-k8s/          # K8s cluster scans
└── summaries/               # Unified reports (all targets)
    ├── findings.json
    ├── SUMMARY.md
    ├── dashboard.html
    └── findings.sarif
```

📖 **Complete multi-target guide:** [docs/USER_GUIDE.md — Multi-Target Scanning](docs/USER_GUIDE.md#multi-target-scanning-v060)

---

## 🎯 Overview

**A unified security platform for scanning code repositories, container images, infrastructure-as-code, web applications, GitLab repos, and Kubernetes clusters.**

This project provides an automated framework for conducting thorough security audits across your entire application stack. It orchestrates multiple industry-standard security tools to detect secrets, vulnerabilities, misconfigurations, and security issues.

### Key Features

- 🎯 **Multi-Target Scanning (v0.6.0+)**: Scan 6 target types in one unified workflow
  - Repositories (source code)
  - Container images (Docker/OCI)
  - IaC files (Terraform/CloudFormation/K8s)
  - Live web URLs (DAST)
  - GitLab repos (verified secrets)
  - Kubernetes clusters (live audits)
- ✅ **Multi-Tool Scanning**: Curated set covering secrets (trufflehog verified, noseyparker), SAST (semgrep, bandit), SBOM+vuln/misconfig (syft+trivy), IaC (checkov), Dockerfile (hadolint), DAST (OWASP ZAP), runtime security (Falco), and fuzzing (AFL++)
  - **v0.5.0 Update:** Removed deprecated tools (gitleaks, tfsec, osv-scanner), added DAST/runtime/fuzzing capabilities
- 📊 **Comprehensive Reporting**: Unified findings (JSON/YAML), enriched SARIF 2.1.0 with taxonomies, Markdown summary, and an interactive HTML dashboard with XSS protection
- 🎨 **Easy-to-Read Outputs**: Well-formatted reports with severity categorization using type-safe enums
- 🔄 **Automated Workflows**: One CLI to scan, aggregate, and gate on severity (scan/report/ci)
- 🧭 **Profiles and Overrides**: Named profiles, per-tool flags/timeouts, include/exclude patterns, configurable thread recommendations
- 🔁 **Resilience**: Timeouts, retries with per-tool success codes, human-friendly logs, graceful cancel
- 🔒 **Security-First**: XSS vulnerability patched, comprehensive input escaping, secure-by-default configurations

## 🚀 Quick Start (Local Installation)

### Install or Update (curated tools)

These targets detect Linux/WSL/macOS and install or upgrade the curated CLI tools used by this suite. They also surface helpful hints if a platform step needs manual action.

```bash
make tools           # one-time install of curated tools
make tools-upgrade   # refresh/upgrade curated tools
make verify-env      # check OS/WSL/macOS and tool availability
make dev-deps        # install Python dev dependencies
```

Optional: install the package locally to get `jmo` and `jmotools` commands on your PATH:

```bash
pip install -e .
```

#### Pre-commit hooks (YAML & Actions validation)

We ship pre-commit hooks for YAML linting and GitHub Actions validation (among other basic checks):

```bash
make pre-commit-install   # installs the git hooks
make pre-commit-run       # run checks on all files
```

These run locally via pre-commit and are also enforced in CI.

We ship a `.yamllint.yaml` and validate GitHub Actions workflows via `actionlint`. The same checks are executed in CI.

#### Reproducible dev dependencies (optional)

This repo ships a `requirements-dev.in` with a compiled `requirements-dev.txt`. Use pip-tools or uv to pin/sync your dev environment:

```bash
make upgrade-pip
make deps-compile   # compile dev deps
make deps-sync      # sync env to compiled lock
```

CI verifies that `requirements-dev.txt` is up to date on PRs. If it fails, run `make deps-compile` and commit the diff.

### Quick Start (Unified CLI)

1. Verify your environment (Linux/WSL/macOS) and see install hints for optional tools:

```bash
make verify-env
```

1. Install Python dev dependencies (for running tests and reporters):

```bash
make dev-deps
```

1. Scan repositories using a profile, then aggregate reports:

```bash
# Scan immediate subfolders under ~/repos with the 'balanced' profile (default)
python3 scripts/cli/jmo.py scan --repos-dir ~/repos --profile-name balanced --human-logs

# Aggregate and write unified outputs to results/summaries
# (positional or --results-dir are both accepted)
python3 scripts/cli/jmo.py report ./results --profile --human-logs
# or
python3 scripts/cli/jmo.py report --results-dir ./results --profile --human-logs
```

#### Multi-target scanning (v0.6.0+)

```bash
# Scan container image
python3 scripts/cli/jmo.py scan --image nginx:latest --human-logs

# Scan Terraform state
python3 scripts/cli/jmo.py scan --terraform-state terraform.tfstate --human-logs

# Scan live web app
python3 scripts/cli/jmo.py scan --url https://example.com --tools zap --human-logs

# Scan everything together
python3 scripts/cli/jmo.py scan \
  --repo ./myapp \
  --image myapp:latest \
  --url https://myapp.com \
  --k8s-context prod \
  --human-logs
```

#### Or do both in one step for CI with a failure threshold

```bash
# Repository CI
python3 scripts/cli/jmo.py ci --repos-dir ~/repos --profile-name fast --fail-on HIGH --profile --human-logs

# Multi-target CI (v0.6.0+)
python3 scripts/cli/jmo.py ci --image myapp:latest --url https://staging.myapp.com --fail-on HIGH --human-logs
```

Outputs include: summaries/findings.json, SUMMARY.md, findings.yaml, findings.sarif (enabled by default), dashboard.html, and timings.json (when profiling).

### Basic Usage

#### Optional: Quick Setup with Helper Script

Use the `populate_targets.sh` helper script to clone multiple repositories for testing (optimized for WSL):

```bash
# Clone sample vulnerable repos (fast shallow clones)
./scripts/core/populate_targets.sh

# Clone from custom list with full history
./scripts/core/populate_targets.sh --list my-repos.txt --full

# Clone with 8 parallel jobs for faster performance
./scripts/core/populate_targets.sh --parallel 8

# Unshallow repos if secret scanners need full git history
./scripts/core/populate_targets.sh --unshallow
```

#### Running Security Scans (legacy shell script)

Prefer the Python CLI above. For legacy flows, you can still use the shell wrapper:

```bash
./scripts/cli/security_audit.sh -d ~/security-testing    # scan
./scripts/cli/security_audit.sh --check                  # verify tools
```

#### End-to-End Workflow

```bash
# 1. Clone test repositories (shallow for speed)
./scripts/core/populate_targets.sh --dest ~/test-repos --parallel 4

# 2. Run security audit (preferred)
python3 scripts/cli/jmo.py ci --repos-dir ~/test-repos --fail-on HIGH --profile --human-logs

# 3. View results
cat results/summaries/SUMMARY.md
# macOS: open results/summaries/dashboard.html
# Linux: xdg-open results/summaries/dashboard.html
```

Looking for screenshots and how to capture them? See: [docs/screenshots/README.md](docs/screenshots/README.md)

## 📚 Documentation

### Workflow (at a glance)

The security audit follows this workflow:

1. **Tool Verification**: Checks all required tools are installed
2. **Repository Scanning**: jmo scan orchestrates tools per jmo.yml (profiles, overrides, retries)
3. **Results Aggregation**: jmo report normalizes tool outputs to a CommonFinding shape
4. **Report Generation**: JSON/MD/YAML/HTML/SARIF and suppression summary
5. **Dashboard Creation**: Self-contained HTML dashboard with an optional profiling panel

### Output Structure (Default)

```text
results/
├── individual-repos/           # Repository scans
│   └── <repo-name>/
│       ├── trufflehog.json
│       ├── semgrep.json
│       ├── syft.json
│       ├── trivy.json
│       ├── checkov.json
│       ├── hadolint.json
│       ├── zap.json           # DAST (balanced + deep)
│       ├── noseyparker.json   # deep only
│       ├── bandit.json        # deep only
│       ├── falco.json         # deep only
│       └── afl++.json         # deep only
├── individual-images/          # ✨ NEW v0.6.0: Container image scans
│   └── <sanitized-image>/
│       ├── trivy.json
│       └── syft.json
├── individual-iac/             # ✨ NEW v0.6.0: IaC file scans
│   └── <file-stem>/
│       ├── checkov.json
│       └── trivy.json
├── individual-web/             # ✨ NEW v0.6.0: Web app/API scans
│   └── <domain>/
│       └── zap.json
├── individual-gitlab/          # ✨ NEW v0.6.0: GitLab scans
│   └── <group>_<repo>/
│       └── trufflehog.json
├── individual-k8s/             # ✨ NEW v0.6.0: K8s cluster scans
│   └── <context>_<namespace>/
│       └── trivy.json
└── summaries/                  # Unified reports (ALL targets)
   ├── findings.json
   ├── findings.yaml        # requires PyYAML
   ├── findings.sarif       # SARIF 2.1.0
   ├── SUMMARY.md
   ├── dashboard.html
   ├── SUPPRESSIONS.md      # written when suppressions apply
   └── timings.json         # written when --profile is used
```

### Reporters

The aggregator writes unified outputs under `results/summaries/`:

- JSON (`findings.json`) — complete, machine-readable findings list
- Markdown (`SUMMARY.md`) — human-readable overview with severity counts and top rules
- YAML (`findings.yaml`) — optional; requires PyYAML
- HTML (`dashboard.html`) — interactive dashboard with filters, sorting, exports, and theme toggle
- SARIF (`findings.sarif`) — 2.1.0 for code scanning integrations
- Suppression summary (`SUPPRESSIONS.md`) — appears when suppression rules filter findings

See `SAMPLE_OUTPUTS.md` for real examples produced from the `infra-demo` fixture.

### How we normalize findings

All tool outputs are converted into a single CommonFinding schema during aggregation. This enables a unified view (JSON/YAML/HTML/SARIF) and consistent gating.

- Schema: [docs/schemas/common_finding.v1.json](docs/schemas/common_finding.v1.json)
- Required fields include: schemaVersion (1.0.0), id, ruleId, severity, tool (name/version), location (path/lines), and message. Optional fields include title, description, remediation, references, tags, cvss, and raw (original tool payload).
- Fingerprint (id): deterministically derived from a stable subset of attributes (tool | ruleId | path | startLine | message snippet) to support cross-tool dedupe. The aggregation step deduplicates by this id.

## 🛠️ Tool Installation

### macOS (Homebrew)

```bash
# Core tools
brew install cloc jq

# Secrets detection
brew install trufflesecurity/trufflehog/trufflehog

# SAST
brew install semgrep

# SBOM + Vuln/Misconfig
brew install syft trivy

# IaC
brew install checkov

# Dockerfile linting
brew install hadolint

# DAST (balanced + deep profiles)
brew install --cask owasp-zap

# Additional tools for deep profile:
# - Nosey Parker: Download from https://github.com/praetorian-inc/noseyparker/releases
# - Falco: brew install falco (or via official installer)
# - AFL++: brew install afl++
```

### Linux (Ubuntu/Debian)

```bash
# Core tools
sudo apt-get install cloc jq

# Secrets detection
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# SAST
pip install semgrep

# SBOM + Vuln/Misconfig
# Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
# Trivy
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install trivy

# IaC
pip install checkov

# Dockerfile linting
sudo wget -O /usr/local/bin/hadolint https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64
sudo chmod +x /usr/local/bin/hadolint

# DAST (balanced + deep profiles)
sudo snap install zaproxy --classic

# Additional tools for deep profile:
# - Nosey Parker: Download from https://github.com/praetorian-inc/noseyparker/releases
# - Bandit: pip install bandit
# - Falco: Follow https://falco.org/docs/getting-started/installation/
# - AFL++: sudo apt-get install afl++
```

### Nosey Parker (manual install)

Nosey Parker doesn’t ship via apt/brew universally. Install the release binary and put it on your PATH:

1. Download the latest release for your OS/arch from:
   <https://github.com/praetorian-inc/noseyparker/releases>

2. Unpack and move the binary onto PATH (example for Linux x86_64):

```bash
tar -xzf noseyparker-*.tar.gz
chmod +x noseyparker
sudo mv noseyparker /usr/local/bin/
noseyparker --version
```

Tip: run `make verify-env` to confirm the tool is detected.

### Nosey Parker on WSL (native recommended) + Docker fallback

On WSL Ubuntu, installing Nosey Parker natively is the most reliable path (prebuilt binaries can hit glibc issues). See “User Guide — Nosey Parker on WSL” for a short build-from-source flow using Rust and Boost. When the local binary is not available or fails to run, the CLI automatically falls back to a Docker-based runner.

The CLI automatically falls back to a Docker-based Nosey Parker runner when the local binary is missing or not runnable (common on older WSL/glibc). When enabled via profiles, scans will transparently produce the expected JSON here:

```text
results/individual-repos/<repo-name>/noseyparker.json
```

Requirements for the fallback:

- Docker installed and running
- Ability to pull or use `ghcr.io/praetorian-inc/noseyparker:latest`

Manual usage (optional):

```bash
bash scripts/core/run_noseyparker_docker.sh \
   --repo /path/to/repo \
   --out results/individual-repos/<repo-name>/noseyparker.json
```

This mounts your repository read-only into the container, scans it, and writes a JSON report to the `--out` path. The CLI uses this same script automatically when needed.

### Semgrep (latest via official script, optional)

If you prefer the bleeding-edge standalone installer maintained by Semgrep:

```bash
curl -sL https://semgrep.dev/install.sh | sh

# Ensure ~/.local/bin is on PATH (the installer places semgrep there by default)
export PATH="$HOME/.local/bin:$PATH"
semgrep --version
```

Note: we recommend isolating CLI tools via pipx or OS packages for stability. The official installer is a convenient alternative when you need the newest release.

## 📋 Advanced Usage

### Helper Scripts for Multi-Repo Scanning

#### `scripts/populate_targets.sh` - Automated Repository Cloning

This helper script streamlines the process of cloning multiple repositories for security scanning, with performance optimizations for WSL environments.

**Features:**

- 🚀 Shallow clones (depth=1) for faster cloning
- ⚡ Parallel cloning for improved performance
- 🔄 Unshallow option for secret scanners requiring full history
- 📝 Reads from repository list file

**Usage Examples:**

```bash
# Basic usage with defaults (samples/repos.txt → ~/security-testing)
./scripts/core/populate_targets.sh

# Custom repository list and destination
./scripts/core/populate_targets.sh --list custom-repos.txt --dest ~/my-test-repos

# Full clones with 8 parallel jobs
./scripts/core/populate_targets.sh --full --parallel 8

# Unshallow existing shallow clones
./scripts/core/populate_targets.sh --dest ~/security-testing --unshallow

# Show all options
./scripts/core/populate_targets.sh --help
```

**Repository List Format (`samples/repos.txt`):**

```text
# One GitHub repository URL per line
# Lines starting with # are comments
https://github.com/user/repo1.git
https://github.com/user/repo2.git
```

**Performance Tips for WSL:**

1. Use shallow clones initially for 10x faster cloning
2. Adjust `--parallel` based on network speed (default: 4)
3. Use `--unshallow` only if secret scanners need full git history
4. Clone to WSL filesystem (not Windows mount) for better performance

### CLI-first usage

Prefer the Python CLI for report generation from existing results:

```bash
# Default reporters (formats controlled by jmo.yml)
python3 scripts/cli/jmo.py report /path/to/results

# Set thread workers explicitly for aggregation
python3 scripts/cli/jmo.py report /path/to/results --threads 6

# Record profiling timings (writes summaries/timings.json)
python3 scripts/cli/jmo.py report /path/to/results --profile

# Human-friendly colored logs (stderr)
python3 scripts/cli/jmo.py report /path/to/results --human-logs
```

### Unified CLI: report-only

After scans complete, you can generate unified, normalized reports via the Python CLI:

```bash
# Default reports (formats controlled by jmo.yml)
python3 scripts/cli/jmo.py report /path/to/security-results

# Set thread workers explicitly for aggregation
python3 scripts/cli/jmo.py report /path/to/security-results --threads 6

# Record profiling timings (writes summaries/timings.json)
python3 scripts/cli/jmo.py report /path/to/security-results --profile

# Human-friendly colored logs (stderr)
python3 scripts/cli/jmo.py report /path/to/security-results --human-logs
```

Or using Make:

```bash
make report RESULTS_DIR=/path/to/security-results THREADS=6
make profile RESULTS_DIR=/path/to/security-results THREADS=6
```

When profiling is enabled, `timings.json` will include aggregate time, a recommended thread count, and per-job timings.

### Unified CLI: scan/ci

```bash
# Scan a single repo with a custom tool subset and timeouts
python3 scripts/cli/jmo.py scan --repo /path/to/repo --tools trufflehog semgrep --timeout 300 --human-logs

# CI convenience – scan then report with gating on severity
python3 scripts/cli/jmo.py ci --repos-dir ~/repos --profile-name balanced --fail-on HIGH --profile
```

### Output Structure (Summaries)

The `summaries/` folder also contains unified outputs:

```text
summaries/
├── findings.json     # Unified normalized findings (machine-readable)
├── SUMMARY.md        # Human-readable summary
├── findings.yaml     # Optional YAML (requires PyYAML)
├── dashboard.html    # Self-contained HTML view
├── findings.sarif    # SARIF 2.1.0 for code scanning
├── SUPPRESSIONS.md   # Suppression summary
└── timings.json      # Profiling (when --profile used)
```

### Profiles, per-tool overrides, retries

You can define named profiles in `jmo.yml` to control which tools run, include/exclude repo patterns, timeouts, and threads. You can also provide per-tool flags and timeouts, and a global retry count for flaky tools.

Example `jmo.yml` snippet:

```yaml
default_profile: balanced
retries: 1
profiles:
   fast:
      tools: [trufflehog, semgrep, trivy]
      include: ["*"]
      exclude: ["big-monorepo*"]
      timeout: 300
      threads: 8
      per_tool:
         semgrep:
            flags: ["--exclude", "node_modules", "--exclude", "dist"]
            timeout: 180
   balanced:
      tools: [trufflehog, semgrep, syft, trivy, checkov, hadolint, zap]
      timeout: 600
      threads: 4
   deep:
      tools: [trufflehog, noseyparker, semgrep, bandit, syft, trivy, checkov, hadolint, zap, falco, afl++]
      timeout: 900
      threads: 2
      retries: 1

per_tool:
   trivy:
      flags: ["--no-progress"]
      timeout: 1200
   zap:
      flags: ["-config", "api.disablekey=true", "-config", "spider.maxDuration=5"]
```

Using a profile from CLI:

```bash
# Scan using profile 'fast' with human-friendly logs
python3 scripts/cli/jmo.py scan --repos-dir ~/repos --profile-name fast --human-logs

# CI convenience: scan then report, failing on HIGH or worse, record timings, use 'deep' profile
python3 scripts/cli/jmo.py ci --repos-dir ~/repos --profile-name deep --fail-on HIGH --profile
```

Retries behavior:

- Global `retries` (or per-profile) retries failed tool commands a limited number of times
- Some tools use non-zero exit to indicate “findings”; we treat those as success codes to avoid useless retries

Human logs show per-tool retry attempts when > 1, e.g.: `attempts={'semgrep': 2}`

### Customizing Tool Execution

Prefer jmo.yml profiles and per_tool overrides. For one-off local tweaks, use:

```bash
python3 scripts/cli/jmo.py scan --repos-dir ~/repos --tools trufflehog semgrep --timeout 300
```

## 📚 Examples, Screenshots, and Testing

- Examples: see `docs/examples/README.md` for common CLI patterns and CI gating.
- Screenshots: `docs/screenshots/README.md` and `docs/screenshots/capture.sh` to generate dashboard visuals.
- Testing: see `TEST.md` for running lint, tests, and coverage locally (CI gate ≥85%).

## 🔍 Understanding Results

### Severity Levels

The toolkit uses a type-safe severity enum with comparison operators for consistent filtering and sorting:

- **CRITICAL**: Verified secrets requiring immediate action
- **HIGH**: Likely secrets or serious vulnerabilities
- **MEDIUM**: Potential issues requiring review
- **LOW**: Minor issues for regular maintenance
- **INFO**: Informational findings

### Key Metrics

- **Total Findings**: All security issues detected
- **Verified Secrets**: Confirmed active credentials (TruffleHog)
- **Unique Issues**: Distinct types of security problems
- **Tool Coverage**: Number of tools that found issues

### Recommendations Priority

1. **Immediate**: Rotate/revoke verified secrets
2. **High Priority**: Fix critical and high severity issues
3. **Medium Priority**: Address medium severity findings
4. **Long-term**: Implement preventive measures

## 🎯 Three-Stage Implementation Strategy

### Stage 1: Pre-commit Hooks

- **Tool**: TruffleHog (verified secrets)
- **Purpose**: Prevent secrets before commit
- **Speed**: Fast (suitable for developer workflow)

### Stage 2: CI/CD Pipeline

- **Tools**: TruffleHog + Semgrep
- **Purpose**: Automated PR/commit scanning
- **Coverage**: Verified secrets + vulnerabilities

### Stage 3: Deep Periodic Audits

- **Tools**: All tools
- **Purpose**: Comprehensive security assessment
- **Frequency**: Weekly/monthly

## 📊 Sample Outputs

For a current snapshot produced from the `infra-demo` fixture, see: [SAMPLE_OUTPUTS.md](SAMPLE_OUTPUTS.md).

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## ❤️ Support

If this toolkit saves you time, consider fueling development with an energy drink.

- Prefer one-time tips? Ko‑fi: <https://ko-fi.com/jmogaming>
- When you’re ready, replace the badge target with your preferred platform: GitHub Sponsors (industry standard), Open Collective, Ko-fi, or Stripe Checkout.
- GitHub Sponsors integrates directly with your GitHub profile and repository sidebar once enabled.

## 📝 License

Dual licensed under your choice of MIT OR Apache 2.0. See [LICENSE](LICENSE), [LICENSE-MIT](LICENSE-MIT), and [LICENSE-APACHE](LICENSE-APACHE).

## 🔗 Related Resources

- [TruffleHog Documentation](https://github.com/trufflesecurity/trufflehog) (verified secrets scanning)
- [Semgrep Documentation](https://semgrep.dev) (multi-language SAST)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/) (vulnerability + misconfig scanning)
- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/) (DAST web security)
- [Falco Documentation](https://falco.org/docs/) (runtime security monitoring)

1. **Start Small**: Test on a single repository first
2. **Review Regularly**: Schedule periodic audits
3. **Act Quickly**: Rotate verified secrets immediately
4. **Prevent Issues**: Implement pre-commit hooks
5. **Monitor Trends**: Track metrics over time

## 🆘 Troubleshooting

### Common Issues

**Problem**: Tools not found

- **Solution**: Run `make verify-env` (or `jmotools setup --check`) to verify installation and get platform-specific hints

**Problem**: JSON parsing errors

- **Solution**: Ensure jq is installed and tools are outputting valid JSON

**Problem**: Permission denied

- **Solution**: Ensure scripts are executable:

```bash
find scripts -type f -name "*.sh" -exec chmod +x {} +
```

**Problem**: Out of memory

- **Solution**: Scan repositories in smaller batches

```bash
./scripts/core/populate_targets.sh --unshallow
```

**Problem**: Path errors (e.g., "//run_security_audit.sh not found")

- **Solution**: This issue has been fixed in the latest version. Update to the latest main branch.
- The wrapper scripts now use absolute paths computed from the script's real path location.

**Problem**: AttributeError when generating dashboard with TruffleHog results

- **Solution**: This has been fixed. The dashboard generator now handles all TruffleHog output formats:
  - JSON arrays: `[{...}, {...}]`
  - Single objects: `{...}`
  - NDJSON (one object per line)
  - Empty files or missing files
  - Nested arrays

### Rebuilding Reports Without Re-Scanning

You can regenerate the dashboard or reports from existing scan results without re-running the security tools:

```bash
# Generate dashboard with default output location
python3 scripts/core/generate_dashboard.py /path/to/results

# Generate dashboard with custom output path (creates parent directories automatically)
python3 scripts/core/generate_dashboard.py /path/to/results /custom/path/dashboard.html

# Example: Generate dashboard in a reports directory
python3 scripts/core/generate_dashboard.py ~/security-results-20251010-120000 ~/reports/security-dashboard.html
```

This is useful when you want to:

- Update the dashboard after manually editing JSON files
- Generate multiple dashboards with different configurations
- Share results by exporting to a specific location

---

**Last Updated**: October 16th, 2025 (v0.6.0)
**Author**: James Moceri
