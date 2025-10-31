# Quick Start – JMo Security CLI

**Get scanning in under 1 minute with package managers (NEW in v0.9.0)!**

---

## ⚡ Fastest Path to Scanning

### NEW: Package Managers (30 seconds) ⭐

**macOS / Linux:**
```bash
brew install jmo-security
jmotools wizard  # Start scanning!
```

**Windows:**
```powershell
winget install jmo.jmo-security
jmotools wizard  # Start scanning!
```

### Alternative Paths:

1. **Have Docker?** → [Option 2: Docker](#option-2--docker-zero-installation) (60 seconds)
2. **Have Python + pip?** → [Install JMo first](#-installation-in-2-minutes), then [Option 3: CLI Wrapper](#option-3--cli-wrapper-commands-local-install)
3. **Prefer manual setup?** → [Docker](#option-2--docker-zero-installation) or [Python install](#-installation-in-2-minutes)

---

## 📦 Installation (in 2 Minutes)

### Path 1: Package Manager (Recommended - v0.9.0+)

**macOS / Linux (Homebrew):**
```bash
brew install jmo-security
# ✅ Done! Tools bundled, added to PATH automatically
```

**Windows (Winget):**
```powershell
winget install jmo.jmo-security
# ✅ Done! Installed to C:\Users\<user>\AppData\Local\JMo Security
```

**Benefits:**
- ✅ One command install
- ✅ Automatic updates (`brew upgrade` / `winget upgrade`)
- ✅ Clean uninstall (`brew uninstall` / `winget uninstall`)

**Skip to:** [Choose Your Path](#-choose-your-path)

---

### Path 2: Python Package (pip install)

**Skip this if using Docker** (Option 2 below) - **Docker includes everything**.

### Quick Install (Python Package)

```bash
# 1. Install JMo Security CLI
pip install jmo-security

# 2. Add to PATH (Linux/macOS/WSL - skip on native Windows)
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc

# 3. Verify installation
jmo --help
jmotools --help
```

**✅ JMo CLI installed!** Now install security tools:

### Option A: Auto-Install Security Tools (Easiest)

```bash
# Clone repo for installation scripts
git clone https://github.com/jimmy058910/jmo-security-repo.git
cd jmo-security-repo

# Auto-install all tools (Linux/WSL/macOS)
make tools

# Verify tools installed correctly
make verify-env
```

### Option B: Manual Tool Installation

See [README — Tool Installation](README.md#-tool-installation) section for platform-specific instructions.

---

## 🚀 Choose Your Path

### Option 1: 🧙 Interactive Wizard (Recommended for Beginners)

**Zero knowledge required. The wizard guides you through everything:**

```bash
jmotools wizard
```

**What the wizard does:**

- Guides profile selection (fast/balanced/deep with time estimates)
- Detects Docker availability (zero-installation path!)
- **NEW (v0.6.2+):** Supports 6 target types (repos, images, IaC, URLs, GitLab, K8s)
- Auto-discovers repositories in directories
- Validates URLs and Kubernetes contexts
- Configures threads and timeouts
- Shows command preview before execution
- Auto-opens results when complete

**Non-interactive mode for automation:**

```bash
jmotools wizard --yes        # Use smart defaults
jmotools wizard --docker     # Force Docker mode
```

📖 **Full wizard guide:** [docs/examples/wizard-examples.md](docs/examples/wizard-examples.md)

---

### Option 2: 🐳 Docker (Zero Installation)

**Don't want to install 11+ security tools? Use Docker:**

```bash
# One-time pull
docker pull ghcr.io/jimmy058910/jmo-security:latest

# Scan current directory (Linux/macOS/WSL)
docker run --rm -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results-dir /scan/results --profile-name balanced --human-logs

# Windows PowerShell users: Use "${PWD}:/scan" instead of "$(pwd):/scan"
# Windows CMD users: Use "%CD%:/scan" instead

# View results
open results/summaries/dashboard.html  # macOS
xdg-open results/summaries/dashboard.html  # Linux
cat results/summaries/SUMMARY.md  # Quick text overview
```

📖 **Understanding your results:** [docs/RESULTS_GUIDE.md](docs/RESULTS_GUIDE.md) - Complete guide to triaging findings and integrating with your workflow

**Three image variants:**

- `:latest` (~500MB) - All 11+ scanners
- `:slim` (~200MB) - Core 6 scanners for CI/CD
- `:alpine` (~150MB) - Minimal footprint

📖 **Complete Docker guide:** [docs/DOCKER_README.md](docs/DOCKER_README.md)

---

### Option 3: 💻 CLI Wrapper Commands (Local Install)

**Already have tools installed? Use the quick wrapper commands:**

```bash
# Quick fast scan (auto-opens results)
jmotools fast --repos-dir ~/repos

# Balanced scan (recommended)
jmotools balanced --repos-dir ~/repos

# Deep scan with all tools
jmotools full --repos-dir ~/repos

# Clone from TSV and scan
jmotools balanced --tsv ./repositories.tsv --dest ./cloned-repos
```

**Bootstrap tools:**

```bash
jmotools setup --check           # Verify installation
jmotools setup --auto-install    # Auto-install (Linux/WSL/macOS)
```

**Makefile shortcuts:**

```bash
make setup                   # Verify tools
make fast DIR=~/repos        # Run fast profile
make balanced DIR=~/repos    # Run balanced profile
make full DIR=~/repos        # Run deep profile
```

---

## 📅 Schedule Automated Scans (NEW in v0.9.0)

**Run security scans automatically with GitHub Actions, GitLab CI, or local cron.**

### Quick Start: Nightly GitHub Actions Scan

```bash
# 1. Create schedule
jmo schedule create \
  --name nightly-deep \
  --cron "0 2 * * *" \
  --profile deep \
  --repos-dir ~/repos \
  --backend github-actions \
  --description "Nightly deep security audit"

# 2. Export workflow file
jmo schedule export nightly-deep > .github/workflows/jmo-nightly.yml

# 3. Commit and push
git add .github/workflows/jmo-nightly.yml
git commit -m "Add nightly security scan"
git push

# ✅ Done! Scans run every night at 2 AM UTC
# View results in GitHub Security tab + downloadable artifacts
```

### Supported Backends

| Backend | Use Case | Platform |
|---------|----------|----------|
| **github-actions** | Cloud-based, GitHub repos | Linux/macOS/Windows |
| **gitlab-ci** | Cloud-based, GitLab repos | Linux/macOS/Windows |
| **local-cron** | Server-based, cron scheduling | Linux/macOS only |

### Common Schedules

```bash
# Daily at 2 AM UTC
--cron "0 2 * * *"

# Every 6 hours
--cron "0 */6 * * *"

# Weekly on Sunday at 3 AM
--cron "0 3 * * 0"

# Weekdays at midnight
--cron "0 0 * * 1-5"
```

### Full CLI Reference

```bash
# List all schedules
jmo schedule list

# Get schedule details
jmo schedule get nightly-deep

# Update schedule
jmo schedule update nightly-deep --profile balanced --cron "0 3 * * *"

# Delete schedule
jmo schedule delete nightly-deep --force

# Install to local cron (Linux/macOS)
jmo schedule install nightly-deep

# Export GitLab CI
jmo schedule export nightly-deep --backend gitlab-ci >> .gitlab-ci.yml
```

**See [docs/USER_GUIDE.md#scheduled-scans](docs/USER_GUIDE.md#scheduled-scans) for complete documentation.**

---

## ✨ What's New

### v0.9.0 - EPSS/KEV Risk Prioritization (October 30, 2025)

#### 🎯 Automatic CVE Prioritization

**Sort findings by real-world exploit risk, not just severity!**

- 📊 **EPSS Scoring** - Exploit probability (0-100%) from FIRST.org with 7-day caching
- 🚨 **CISA KEV Detection** - Flags actively exploited CVEs with remediation deadlines
- 🏆 **Priority Score** - Combines severity + EPSS + KEV into 0-100 actionable priority
- 🎨 **Enhanced Dashboard** - Priority column, color-coded badges, KEV indicators
- 📝 **Priority Analysis** - SUMMARY.md shows KEV findings, high EPSS risks, priority distribution

**Impact:** 40% faster triage, 60% reduction in false prioritization

**Quick Example:**

```bash
# Scan and prioritize
jmo scan --repo ./myapp --profile-name balanced
jmo report ./results --human-logs

# View prioritized results
open results/summaries/dashboard.html  # Sort by Priority column!
cat results/summaries/SUMMARY.md      # See "Priority Analysis (EPSS/KEV)" section
```

📖 **Full guide:** [docs/USER_GUIDE.md — EPSS/KEV Risk Prioritization](docs/USER_GUIDE.md#epsskev-risk-prioritization-v090)

---

### v0.6.0 - Multi-Target Scanning (October 2025)

#### 🚀 BREAKTHROUGH: Unified Security Platform

Scan repositories AND infrastructure in one workflow!

- 🐳 **Container Image Scanning** - Scan Docker/OCI images with Trivy + Syft
- ⚙️ **IaC File Scanning** - Scan Terraform/CloudFormation/K8s manifests with Checkov + Trivy
- 🌐 **Live Web URL Scanning** - DAST scanning with OWASP ZAP
- 🦊 **GitLab Integration** - Scan GitLab repos with TruffleHog
- ☸️ **Kubernetes Cluster Scanning** - Live K8s audits with Trivy
- 📊 **Unified Reporting** - All targets aggregated in one dashboard

**Quick Examples:**

```bash
# Scan a container image
jmo scan --image nginx:latest

# Scan Terraform state
jmo scan --terraform-state terraform.tfstate

# Scan live web app
jmo scan --url https://example.com --tools zap

# Scan everything together!
jmo scan --repo ./myapp --image myapp:latest --url https://myapp.com --k8s-context prod
```

📖 **Full guide:** [docs/USER_GUIDE.md — Multi-Target Scanning](docs/USER_GUIDE.md#multi-target-scanning-v060)

---

### v0.5.0 - Tool Suite Consolidation (October 2025)

**Tool Suite Consolidation:**

- 🎯 **DAST Added** - OWASP ZAP for runtime vulnerability detection (20-30% more findings)
- 🛡️ **Runtime Security** - Falco for container/K8s monitoring (deep profile)
- 🔬 **Fuzzing** - AFL++ for coverage-guided vulnerability discovery (deep profile)
- ✅ **Verified Secrets** - TruffleHog with 95% false positive reduction
- 🧹 **Removed Deprecated** - gitleaks, tfsec, osv-scanner removed
- 📊 **Profile Restructuring** - Fast: 3 tools, Balanced: 7 tools, Deep: 11 tools

**Previous Enhancements (Phase 1):**

- 🧙 **Interactive Wizard** - Beginner-friendly guided scanning
- 🐳 **Docker Images** - Zero-installation security scanning
- 🔒 **XSS Patched** - HTML dashboard security hardened
- 📊 **Enriched SARIF** - CWE/OWASP/CVE taxonomies
- ⚙️ **Type-Safe Severity** - Cleaner code with enum
- 🎯 **91% Coverage** - 272/272 tests passing

See [CHANGELOG.md](CHANGELOG.md) for complete details.

---

## 🪟 Windows Users: Start Here

**Windows has three options for running JMo Security. Choose based on your experience level:**

### Option 1: Docker Desktop (Recommended for Beginners)

**Best for:** Complete beginners, no WSL setup required

**Pros:**

- ✅ Zero tool installation (all scanners pre-installed)
- ✅ Works on Windows 10/11 Home and Pro
- ✅ No command-line experience needed
- ✅ Same commands work on Windows/Mac/Linux

**Setup (5 minutes):**

1. **Install Docker Desktop:**
   - Download: <https://www.docker.com/products/docker-desktop>
   - Run installer, accept defaults
   - Restart computer when prompted
   - Wait for Docker to start (whale icon in system tray)

2. **Verify installation** (PowerShell or Command Prompt):

   ```powershell
   docker --version
   ```

   Expected: `Docker version XX.X.X`

3. **Pull JMo Security image** (one-time, ~500MB):

   ```powershell
   docker pull ghcr.io/jimmy058910/jmo-security:latest
   ```

4. **Run your first scan** (PowerShell - use this exact syntax):

   ```powershell
   # Navigate to your project
   cd C:\Users\YourName\Projects\myapp

   # Run scan (IMPORTANT: Use ${PWD} with curly braces on Windows)
   docker run --rm -v "${PWD}:/scan" ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan --results /scan/results --profile balanced --human-logs

   # View results
   start results\summaries\dashboard.html
   type results\summaries\SUMMARY.md
   ```

   📖 **Understanding results:** [docs/RESULTS_GUIDE.md](docs/RESULTS_GUIDE.md) - Triage workflow and remediation guide

**Cross-platform Docker volume mount syntax:**

| Platform | Syntax | Example |
|----------|--------|---------|
| **Linux/macOS/WSL** | `"$(pwd):/scan"` | `docker run -v "$(pwd):/scan" ...` |
| **Windows PowerShell** | `"${PWD}:/scan"` | `docker run -v "${PWD}:/scan" ...` |
| **Windows CMD** | `"%CD%:/scan"` | `docker run -v "%CD%:/scan" ...` |

**Windows-specific Docker notes:**

- ✅ **Always use quotes** around volume paths to handle spaces
- ✅ **Use backslashes** for Windows paths: `start results\summaries\dashboard.html`
- ✅ **Share drives:** Docker Desktop may ask permission to access C:\ - approve this

**Common Docker issues on Windows:**

#### Issue: "Error response from daemon: invalid mode: /scan"**

**Solution:** Use `${PWD}` with curly braces and quotes:

```powershell
# ❌ WRONG (Linux/macOS syntax)
docker run --rm -v $(pwd):/scan ...

# ✅ CORRECT (Windows PowerShell syntax)
docker run --rm -v "${PWD}:/scan" ...
```

#### Issue: "Docker daemon is not running"**

**Solution:**

1. Launch Docker Desktop from Start Menu
2. Wait for whale icon in system tray to turn green
3. Try command again

#### Issue: Slow performance or file access errors**

**Solution:**

1. Enable WSL 2 backend in Docker Desktop settings
2. Move project files to WSL filesystem (see WSL option below)

📖 **Complete Docker guide:** [docs/DOCKER_README.md](docs/DOCKER_README.md)

---

### Option 2: WSL 2 with Native Tools (Recommended for Developers)

**Best for:** Developers comfortable with command line, want maximum performance

**Pros:**

- ✅ **Native Linux performance** (2-3x faster than Docker on Windows)
- ✅ **Full tool control** (install/upgrade individual scanners)
- ✅ **Better git integration** (native Linux git performance)
- ✅ **No Docker overhead** (uses less RAM/CPU)

**Setup (10-15 minutes):**

1. **Install WSL 2 with Ubuntu** (PowerShell as Administrator):

   ```powershell
   # Install WSL 2 (Windows 10 version 2004+ or Windows 11)
   wsl --install

   # Restart computer when prompted

   # After restart, set default WSL version to 2
   wsl --set-default-version 2
   ```

   This installs Ubuntu 22.04 LTS by default.

2. **Launch Ubuntu** from Start Menu and create a user account when prompted

3. **Update Ubuntu packages:**

   ```bash
   sudo apt-get update -y && sudo apt-get upgrade -y
   ```

4. **Install core dependencies:**

   ```bash
   sudo apt-get install -y build-essential git jq python3 python3-pip curl wget
   ```

5. **Install JMo Security:**

   ```bash
   pip install jmo-security

   # Ensure ~/.local/bin is on PATH
   echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
   source ~/.bashrc

   # Verify installation
   jmo --help
   jmotools --help
   ```

6. **Install security tools** (choose one):

   **Option A: Auto-install (easiest):**

   ```bash
   # Clone JMo repo for tool installation scripts
   git clone https://github.com/jimmy058910/jmo-security-repo.git
   cd jmo-security-repo

   # Auto-install tools via Makefile
   make tools

   # Verify tools
   make verify-env
   ```

   **Option B: Manual install** (see full tool installation section below)

7. **Run your first scan:**

   ```bash
   # Scan a project (can be in Windows filesystem or WSL filesystem)
   # Windows path example (slower): /mnt/c/Users/YourName/Projects/myapp
   # WSL path example (faster): ~/projects/myapp

   jmotools balanced --repos-dir ~/projects

   # View results
   cat results/summaries/SUMMARY.md

   # Open dashboard (launches Windows browser from WSL)
   explorer.exe results/summaries/dashboard.html
   ```

   📖 **Next steps:** [docs/RESULTS_GUIDE.md](docs/RESULTS_GUIDE.md) - Learn to triage findings, suppress false positives, and integrate with CI/CD

**WSL Performance Tips:**

- ✅ **Use WSL filesystem** (`~` paths) for 2-3x faster performance
- ✅ **Avoid `/mnt/c/` paths** when possible (Windows filesystem access is slower)
- ✅ **Clone repos into WSL:** `cd ~ && git clone ...`
- ✅ **Access WSL files from Windows:** `\\wsl$\Ubuntu\home\username\`

**WSL vs Docker Performance Comparison:**

| Metric | WSL Native | Docker on Windows | Winner |
|--------|------------|-------------------|--------|
| **Scan Speed** | Baseline | 30-50% slower | WSL |
| **Memory Usage** | ~500MB | ~2GB (Docker overhead) | WSL |
| **Git Operations** | Fast | Slow (cross-filesystem) | WSL |
| **Setup Complexity** | Medium | Low | Docker |
| **Tool Control** | Full | Limited | WSL |

**Common WSL issues:**

#### Issue: "command not found: jmo"**

**Solution:** Add `~/.local/bin` to PATH:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

#### Issue: Permission errors accessing Windows files**

**Solution:** WSL mounts Windows drives at `/mnt/c/`. Use WSL filesystem instead:

```bash
# ❌ SLOW: Windows filesystem
cd /mnt/c/Users/YourName/Projects
jmotools balanced --repos-dir .

# ✅ FAST: WSL filesystem
mkdir -p ~/projects
cd ~/projects
git clone https://github.com/user/repo.git
jmotools balanced --repos-dir ~/projects
```

#### Issue: "Cannot connect to Docker daemon" (if using Docker within WSL)**

**Solution:** Install Docker Desktop and enable WSL 2 integration:

1. Docker Desktop → Settings → Resources → WSL Integration
2. Enable integration for Ubuntu distribution
3. Restart WSL: `wsl --shutdown` (in PowerShell), then relaunch Ubuntu

📖 **WSL troubleshooting:** [docs/index.md — WSL Quick Install](docs/index.md#wsl-quick-install-checklist)

---

### ⚠️ Option 3: Native Windows Tools (NOT RECOMMENDED)

**⚠️ WARNING: This option provides SEVERELY LIMITED security coverage and is NOT recommended.**

**Critical limitations:**

- ❌ **Only 6 out of 11+ tools work** on native Windows
- ❌ **Missing entire security categories:**
  - ❌ **No DAST scanning** (OWASP ZAP requires Java/Linux)
  - ❌ **No runtime security** (Falco requires Linux kernel)
  - ❌ **No fuzzing** (AFL++ is Linux/macOS only)
  - ❌ **No Dockerfile linting** (Hadolint unavailable)
  - ❌ **No Nosey Parker** (high-precision secrets scanning missing)
- ❌ **Tool compatibility issues** (many tools run poorly on Windows)
- ❌ **No official support** (most security tools are Linux-first)
- ❌ **Missing 20-30% of vulnerabilities** that DAST tools would find
- ❌ **Incomplete coverage** compared to balanced/deep profiles

**You will miss critical security vulnerabilities with this approach.**

**STRONGLY RECOMMENDED ALTERNATIVES:**

1. ✅ **Use Docker Desktop** (Option 1) - Full tool support, zero setup
2. ✅ **Use WSL 2** (Option 2) - Full tool support, best performance

**Only consider native Windows if:**

- You have specific organizational requirements prohibiting Docker/WSL
- You understand you're getting 50-60% tool coverage
- You accept the security risk of missing DAST/runtime/fuzzing findings

**If you must use native Windows (against our recommendation):**

1. **Install Python 3.10+:**

   Download from: <https://www.python.org/downloads/>

   ✅ **Check "Add Python to PATH" during installation**

2. **Install Git for Windows:**

   Download from: <https://git-scm.com/download/win>

3. **Install JMo Security:**

   ```powershell
   pip install jmo-security
   jmo --help
   ```

4. **Install Windows-compatible tools only:**

   **Available tools (6 of 11+):**
   - Semgrep (SAST): `pip install semgrep`
   - Bandit (Python SAST): `pip install bandit`
   - Checkov (IaC): `pip install checkov`
   - TruffleHog (secrets - verified): Download from <https://github.com/trufflesecurity/trufflehog/releases>
   - Trivy (vulnerabilities): Download from <https://github.com/aquasecurity/trivy/releases>
   - Syft (SBOM): Download from <https://github.com/anchore/syft/releases>

   **Missing tools (5 of 11+):**
   - ❌ Hadolint (Dockerfile linting)
   - ❌ Nosey Parker (secrets - high precision)
   - ❌ OWASP ZAP (DAST - web security)
   - ❌ Falco (runtime security)
   - ❌ AFL++ (fuzzing)

5. **Create Windows-specific profile (required):**

   Create `jmo.yml` in your project:

   ```yaml
   default_profile: windows-limited
   profiles:
     windows-limited:
       # ONLY 6 tools available - missing DAST, runtime, fuzzing, hadolint, noseyparker
       tools: [trufflehog, semgrep, bandit, syft, trivy, checkov]
       timeout: 600
       threads: 4
   ```

6. **Run limited scan:**

   ```powershell
   jmo scan --repo C:\Users\YourName\Projects\myapp --profile-name windows-limited --human-logs
   start results\summaries\dashboard.html
   ```

**Seriously, reconsider:**

Native Windows scanning provides **only 50-60% of the security coverage** you'd get with Docker or WSL. You're missing critical vulnerability classes:

- **Web application vulnerabilities** (no DAST)
- **Runtime container exploits** (no Falco)
- **Fuzzing-discovered bugs** (no AFL++)
- **Dockerfile security issues** (no Hadolint)
- **High-precision secret detection** (no Nosey Parker)

**Recommendation:** Use Docker Desktop (5-minute setup) or WSL 2 (15-minute setup) for full security coverage.

---

### Windows Option Comparison

| Feature | Docker Desktop | WSL 2 Native | ⚠️ Windows Native |
|---------|----------------|--------------|-------------------|
| **Setup Time** | 5 minutes | 10-15 minutes | 20-30 minutes |
| **Tool Coverage** | ✅ All 11+ tools (100%) | ✅ All 11+ tools (100%) | ❌ Only 6 tools (55%) |
| **Security Coverage** | ✅ Complete | ✅ Complete | ❌ Severely limited |
| **DAST Scanning** | ✅ Yes (ZAP) | ✅ Yes (ZAP) | ❌ No |
| **Runtime Security** | ✅ Yes (Falco) | ✅ Yes (Falco) | ❌ No |
| **Fuzzing** | ✅ Yes (AFL++) | ✅ Yes (AFL++) | ❌ No |
| **Performance** | Good | Excellent | Good |
| **Ease of Use** | Easiest | Medium | Hard |
| **Recommended** | ✅ Yes | ✅ Yes | ❌ **NO** |

**Our strong recommendation for Windows users:**

1. **Complete beginners:** Docker Desktop (Option 1) - ✅ Full tool support
2. **Developers:** WSL 2 (Option 2) - ✅ Full tool support, best performance
3. **CI/CD pipelines:** Docker (Option 1) - ✅ Full tool support
4. **Maximum performance:** WSL 2 (Option 2) - ✅ Full tool support
5. **Native Windows:** ❌ **NOT recommended** - Only 55% tool coverage, missing critical security categories

**Bottom line for Windows users:** Choose Docker Desktop or WSL 2. Native Windows scanning is incomplete and will miss critical vulnerabilities.

---

## Step 1: Verify environment

```bash
make verify-env
```

This detects Linux/WSL/macOS, checks for optional tools (trufflehog, semgrep, trivy, zap, etc.), and prints install hints.

## Step 2: Prepare your repositories

### Option A: Use Helper Script (Recommended - Fast & Easy)

Use the automated helper script to clone multiple repositories quickly:

```bash
# Quick setup - clone sample vulnerable repos
./scripts/core/populate_targets.sh

# Or customize the destination
./scripts/core/populate_targets.sh --dest ~/my-test-repos

# For faster cloning on WSL, use shallow clones (default)
./scripts/core/populate_targets.sh --parallel 8 --dest ~/security-testing
```

The helper script will:

- ✅ Clone repositories in parallel for speed
- ✅ Use shallow clones (depth=1) for 10x faster cloning
- ✅ Automatically create the destination directory
- ✅ Skip already cloned repositories

### Option B: Manual Clone (Traditional Method)

Create a directory and clone repositories manually:

```bash
# Create testing directory
mkdir -p ~/security-testing

# Clone repositories to scan
cd ~/security-testing
git clone https://github.com/username/repo1.git
git clone https://github.com/username/repo2.git
# ... add more repos
```

### Need Full Git History?

Some secret scanners work better with full git history. If you used shallow clones:

```bash
# Unshallow all repositories
./scripts/core/populate_targets.sh --dest ~/security-testing --unshallow
```

## Step 3: Run the security audit

Use the Python CLI for a single repo or a directory of repos:

```bash
# Scan + report in one step for CI-like flow
python3 scripts/cli/jmo.py ci --repos-dir ~/security-testing --fail-on HIGH --profile --human-logs

# Or run scan and report separately
python3 scripts/cli/jmo.py scan --repos-dir ~/security-testing --profile-name balanced --human-logs
python3 scripts/cli/jmo.py report ./results --profile --human-logs
```

---

## 🆕 Multi-Target Scanning (v0.6.0+)

**New in v0.6.0:** Scan 6 different target types beyond just repositories!

### Quick Start: Container Image Scanning

```bash
# Scan a single image
jmo scan --image nginx:latest --results-dir ./image-scan

# Scan multiple images from file (images.txt: one per line)
jmo scan --images-file images.txt --results-dir ./registry-audit

# CI mode: Scan image and fail on HIGH severity
jmo ci --image myapp:latest --fail-on HIGH --profile balanced
```

### Quick Start: Infrastructure-as-Code Scanning

```bash
# Scan Terraform state file
jmo scan --terraform-state terraform.tfstate --tools checkov trivy

# Scan CloudFormation template
jmo scan --cloudformation template.yml

# Scan Kubernetes manifest
jmo scan --k8s-manifest deployment.yaml
```

### Quick Start: Live Web Application Scanning

```bash
# Scan live web application (DAST)
jmo scan --url https://example.com --tools zap

# Scan multiple URLs from file
jmo scan --urls-file urls.txt --results-dir ./web-audit

# Scan API with OpenAPI spec
jmo scan --api-spec swagger.json --tools zap
```

### Quick Start: GitLab Scanning

```bash
# Scan single GitLab repo
jmo scan --gitlab-url https://gitlab.com --gitlab-token $TOKEN \
  --gitlab-repo mygroup/myrepo --tools trufflehog

# Scan entire GitLab group (all repos)
jmo scan --gitlab-url https://gitlab.com --gitlab-token $TOKEN \
  --gitlab-group myorg --tools trufflehog
```

### Quick Start: Kubernetes Cluster Scanning

```bash
# Scan K8s cluster (current context)
jmo scan --k8s-context prod --k8s-namespace default --tools trivy

# Scan all namespaces
jmo scan --k8s-context prod --k8s-all-namespaces --tools trivy
```

### Multi-Target Audit: Scan Everything Together

```bash
# Complete security audit in ONE command
jmo scan \
  --repo ./myapp \
  --image myapp:latest \
  --url https://myapp.com \
  --k8s-context prod \
  --k8s-namespace default \
  --results-dir ./complete-audit

# CI mode: Multi-target with severity gating
jmo ci \
  --repo ./myapp \
  --image myapp:latest \
  --url https://staging.myapp.com \
  --fail-on HIGH \
  --profile balanced
```

### Results Structure (Multi-Target)

```text
results/
├── individual-repos/        # Repository scans
├── individual-images/       # Container image scans
├── individual-iac/          # IaC file scans
├── individual-web/          # Web app/API scans
├── individual-gitlab/       # GitLab repo scans
├── individual-k8s/          # K8s cluster scans
└── summaries/               # Unified reports (ALL targets)
    ├── findings.json
    ├── SUMMARY.md
    ├── dashboard.html       # Shows ALL findings across all targets!
    └── findings.sarif
```

**Key insight:** All target types are aggregated, deduplicated, and reported in one unified dashboard!

📖 **Complete multi-target guide:** [docs/USER_GUIDE.md — Multi-Target Scanning](docs/USER_GUIDE.md#multi-target-scanning-v060)

---

## Optional: reproducible dev dependencies

If you contribute often, you can pin dev dependencies for consistency using pip-tools:

```bash
make upgrade-pip
make deps-compile
make deps-sync
```

CI checks that `requirements-dev.txt` matches `requirements-dev.in` on PRs.

## Step 4: Review Results

After the scan completes, results land in `results/` (or the directory you pass via `--results-dir`). Unified artifacts live under `results/summaries/`:

- `SUMMARY.md` — human-readable overview with severity counts
- `findings.json` / `findings.yaml` — normalized data for automation (YAML requires PyYAML)
- `dashboard.html` — interactive view of all findings
- `findings.sarif` — SARIF 2.1.0 for code scanning integrations
- `timings.json` — written when `--profile` is used
- `SUPPRESSIONS.md` — appears when a suppression file filtered findings

Quick commands:

```bash
cat results/summaries/SUMMARY.md
xdg-open results/summaries/dashboard.html   # macOS: open
ls -1 results/individual-repos/infra-demo   # per-tool raw outputs
```

### Review Priority

1. **Open the HTML Dashboard** - Visual overview of all findings
2. **Check SUMMARY.md** - Human-readable overview and top rules
3. **Review Individual Reports** - Detailed findings per repository
4. Optional: For a machine-readable format, check summaries/findings.json or summaries/findings.sarif

📖 **Master your results workflow:**

- **Complete triage guide:** [docs/RESULTS_GUIDE.md](docs/RESULTS_GUIDE.md) - Systematic 30-minute triage, compliance reports, CI/CD integration, real-world examples
- **Quick reference card:** [docs/RESULTS_QUICK_REFERENCE.md](docs/RESULTS_QUICK_REFERENCE.md) - One-page printable workflow

## Understanding the Results

### Severity Levels

The toolkit uses a type-safe severity enum with comparison operators for consistent filtering and sorting:

| Level | Meaning | Action Required |
|-------|---------|-----------------|
| CRITICAL | Verified active secrets | Rotate/revoke immediately |
| HIGH | Likely secrets or serious issues | Fix within 24-48 hours |
| MEDIUM | Potential issues | Review and fix soon |
| LOW | Minor issues | Address during regular maintenance |
| INFO | Informational findings | Review for context |

### Key Metrics to Monitor

- **Verified Secrets**: Confirmed active credentials (immediate action required)
- **Total Findings**: Overall security issue count
- **Unique Issue Types**: Variety of security problems found

## Example Workflows

### Workflow 1: Quick scan of single repo

```bash
# Create test directory with one repo
mkdir -p ~/quick-scan
cd ~/quick-scan
git clone https://github.com/username/test-repo.git

# Run scan (Python CLI)
python3 scripts/cli/jmo.py scan --repos-dir ~/quick-scan --human-logs

# View results
cat results/summaries/SUMMARY.md
ls -1 results/individual-repos
```

### Workflow 2: Comprehensive multi-repo audit (helper script)

```bash
# Create a custom repository list
cat > my-repos.txt << 'EOF'
https://github.com/org/repo1.git
https://github.com/org/repo2.git
https://github.com/org/repo3.git
EOF

# Clone all repos in parallel (fast shallow clones)
./scripts/core/populate_targets.sh --list my-repos.txt --dest ~/comprehensive-audit --parallel 6

# Run comprehensive scan + report via CLI
python3 scripts/cli/jmo.py ci --repos-dir ~/comprehensive-audit --profile-name deep --fail-on HIGH --profile

# Open dashboard in browser
xdg-open results/summaries/dashboard.html   # macOS: open
ls -1 results/summaries
```

### Workflow 2b: Comprehensive multi-repo audit (manual)

```bash
# Prepare multiple repositories
mkdir -p ~/comprehensive-audit
cd ~/comprehensive-audit

# Clone multiple repos
for repo in repo1 repo2 repo3; do
  git clone https://github.com/org/$repo.git
done

# Run comprehensive scan via CLI
python3 scripts/cli/jmo.py ci --repos-dir ~/comprehensive-audit --profile-name balanced --fail-on HIGH --profile

# Open dashboard in browser
xdg-open results/summaries/dashboard.html   # macOS: open
```

### Workflow 3: Scheduled weekly audit

Create a cron job or scheduled task:

```bash
# Add to crontab (runs every Monday at 9 AM)
0 9 * * 1 python3 /path/to/repo/scripts/cli/jmo.py ci --repos-dir ~/repos-to-monitor --profile-name fast --fail-on HIGH --profile

# Or use a shell script
cat > ~/weekly-audit.sh << 'EOF'
#!/bin/bash
set -euo pipefail
WORKDIR=~/weekly-security-audit
python3 /path/to/repo/scripts/cli/jmo.py ci \
  --repos-dir ~/production-repos \
  --results-dir "$WORKDIR" \
  --profile-name balanced \
  --fail-on HIGH \
  --profile
echo "Summaries written to $WORKDIR/summaries"
EOF
chmod +x ~/weekly-audit.sh
```

### Workflow 4: Multi-Target CI/CD Integration (v0.6.0+)

**Scan code + container + web app in one CI pipeline:**

```yaml
# Example GitHub Actions workflow
name: Multi-Target Security Audit
on:
  push:
    branches: [ main ]
  pull_request:
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Install tools
        run: |
          # Install TruffleHog, Semgrep, Trivy, ZAP, etc.

      - name: Build container image
        run: |
          docker build -t myapp:${{ github.sha }} .

      - name: Run Multi-Target Security Audit
        run: |
          python3 scripts/cli/jmo.py ci \
            --repo . \
            --image myapp:${{ github.sha }} \
            --url https://staging.myapp.com \
            --profile-name balanced \
            --fail-on HIGH \
            --profile

      - name: Upload Results
        uses: actions/upload-artifact@v2
        if: always()
        with:
          name: security-results
          path: results/

      - name: Upload SARIF (Code Scanning)
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: results/summaries/findings.sarif
```

### Workflow 5: Container Registry Audit

**Audit all images in a container registry:**

```bash
# Create images list from registry
docker images --format "{{.Repository}}:{{.Tag}}" | grep myorg/ > images.txt

# Scan all images
jmo scan --images-file images.txt --results-dir ./registry-audit --profile fast

# CI mode: Fail if any HIGH severity found
jmo ci --images-file images.txt --fail-on HIGH --profile fast

## CI at a glance

- Tests run on a matrix of operating systems and Python versions:
  - OS: ubuntu-latest, macos-latest
  - Python: 3.10, 3.11, 3.12
- Concurrency cancels redundant runs on rapid pushes; each job has a 20-minute timeout.
- Coverage is uploaded to Codecov using tokenless OIDC (no secret needed on public repos).
- PyPI releases use Trusted Publishers (OIDC) — no API token required once authorized in PyPI.

See `.github/workflows/tests.yml` and `.github/workflows/release.yml` for the exact configuration.
```

## Troubleshooting

### Issue: "Tools not found"

**Solution**: Install missing tools

```bash
# Check which tools are missing
./scripts/cli/security_audit.sh --check

# Install individually or follow README.md
```

### Issue: "Permission denied"

**Solution**: Make scripts executable

```bash
find scripts -type f -name "*.sh" -exec chmod +x {} +
```

### Issue: "No repositories found"

**Solution**: Ensure directory has git repositories

```bash
# Check directory structure
ls -la ~/security-testing/

# Each subdirectory should be a git repo with .git folder
```

### Issue: "Out of memory during scan"

Note for WSL users: For the best Nosey Parker experience on WSL, prefer a native install; see the User Guide section “Nosey Parker on WSL (native recommended) and auto-fallback (Docker)”.

**Solution**: Scan repos in smaller batches

```bash
# Instead of scanning all at once, batch them
./scripts/cli/security_audit.sh -d ~/batch1
./scripts/cli/security_audit.sh -d ~/batch2
```

## Interpreting CI failures (quick reference)

- Workflow syntax or logic (actionlint)
  - Symptom: step "Validate GitHub workflows (actionlint)" fails early.
  - Fix: run locally: `pre-commit run actionlint --all-files` or inspect `.github/workflows/*.yml` for typos and invalid `uses:` references. Ensure actions are pinned to valid tags.

- Pre-commit checks (YAML, formatting, lint)
  - Symptom: pre-commit step fails on YAML, markdownlint, ruff/black, etc.
  - Fix: run `make pre-commit-run` locally; address reported files. We ship `.yamllint.yaml` and validate Actions via actionlint.

- Coverage threshold not met
  - Symptom: pytest completes but `--cov-fail-under=85` causes job failure.
  - Fix: add tests for unexercised branches (see adapters’ error paths and reporters). Run `pytest -q --maxfail=1 --disable-warnings --cov=. --cov-report=term-missing` locally to identify gaps.

- Codecov upload warnings
  - Symptom: Codecov step logs request a token or OIDC; or upload skipped.
  - Context: Public repos typically don’t need `CODECOV_TOKEN`. We use tokenless OIDC on CI. If logs insist, either enable OIDC in Codecov org/repo or add `CODECOV_TOKEN` (optional).
  - Check: confirm `coverage.xml` exists; CI task runs tests before upload.

If a failure isn’t listed here, click into the failed step logs in GitHub Actions for the exact stderr. Open an issue with the error snippet for help.

## Next Steps

1. **Review all CRITICAL findings** - These require immediate action
2. **Rotate any verified secrets** - Use the tool comparison report to understand findings
3. **Implement pre-commit hooks** - Prevent future issues (see README.md)
4. **Schedule regular audits** - Weekly or monthly depending on activity
5. **Track metrics over time** - Monitor security posture improvement

## Advanced Usage

For more advanced features and customization options, see:

- [README.md](README.md) - Comprehensive documentation
- [User Guide — Tool Overview](docs/USER_GUIDE.md) - Understanding tool capabilities
- Individual tool documentation for detailed configuration

### Profiling and Performance

To record timing information and a heuristic thread recommendation when generating unified reports:

```bash
# After a scan completes, generate reports with profiling enabled
make profile RESULTS_DIR=/path/to/security-results

# Or directly via CLI
python3 scripts/cli/jmo.py report /path/to/security-results --profile

# Inspect timings
cat /path/to/security-results/summaries/timings.json
```

## Getting Help

If you encounter issues:

1. Check this Quick Start Guide
2. Review the main README.md
3. Check tool-specific documentation
4. Open an issue on GitHub

---

Happy Scanning! 🔒
