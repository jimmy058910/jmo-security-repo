# Interactive Wizard Examples

The JMo Security Wizard provides a guided, interactive experience for beginners to perform security scans without needing to know command-line flags.

> **🪟 Windows Users:** The wizard automatically detects Docker and recommends Docker mode for the best experience. WSL2 + Docker Desktop provides zero-installation scanning with full tool compatibility. See [Windows Setup](#windows-docker-mode) below.

## Table of Contents

- [Five Workflow Types (v0.9.0+)](#five-workflow-types-v090)
- [Visual Interface (v0.9.0+)](#visual-interface-v090)
- [Basic Interactive Mode](#basic-interactive-mode)
- [Non-Interactive Mode](#non-interactive-mode)
- [Docker Mode (Zero Installation)](#docker-mode-zero-installation)
- [Windows Docker Mode](#windows-docker-mode)
- [Multi-Target Scanning (v0.6.2+)](#multi-target-scanning-v062)
- [Privacy-First Telemetry (v0.7.0+)](#privacy-first-telemetry-v070)
- [Artifact Generation](#artifact-generation)
- [Common Workflows](#common-workflows)

---

## Visual Interface (v0.9.0+)

**NEW in v0.9.0:** Enhanced visual interface with progress tracking, colored output, and structured information displays.

### Progress Tracking

The wizard now displays a 6-step progress bar during execution:

```text
→ [Step 1/6] Detecting scan targets...  [████░░░░░░░░░░░░░░░░] 17%
✅ Detected 3 targets

→ [Step 2/6] Gathering configuration options...  [████████░░░░░░░░░░░░] 33%

╔════════════════════════════════════════════════════════════════════╗
║               🚀  Pre-Deployment Security Checklist  🚀               ║
╚════════════════════════════════════════════════════════════════════╝

┌─ 🔍 Detected Deployment Targets ──────────────────────────────────
│ • Container images: 2 detected
│   → nginx:latest
│   → postgres:14
│ • IaC files: 3 detected
│   → main.tf
│   → variables.tf
│   → outputs.tf
│ • Web URLs: 1 detected for DAST
│   → http://localhost:8080
└────────────────────────────────────────────────────────────────────

ℹ️  Auto-detected environment: staging

→ [Step 3/6] Building scan command...  [████████████░░░░░░░░] 50%
✅ Command built successfully

→ [Step 4/6] Preparing preflight summary...  [████████████████░░░░] 67%

┌─ 🚀 Preflight Check ───────────────────────────────────────────────
│ • Profile: balanced
│ • Command: jmo ci --profile balanced --fail-on HIGH --image nginx:latest
│ • Estimated time: 15-20 minutes
└────────────────────────────────────────────────────────────────────

→ [Step 5/6] Awaiting confirmation...  [████████████████████░] 83%
Execute scan? [Y/n]: y

→ [Step 6/6] Executing security scan...  [████████████████████] 100%
ℹ️  Scan in progress... This may take several minutes.
✅ Scan completed successfully!
```

### Visual Elements

**Unicode Box Drawing:**

- Elegant headers with double-line borders: `╔═╗║╚╝`
- Summary boxes with single-line borders: `┌─└│`

**Progress Bars:**

- Filled blocks: `████` (completed)
- Empty blocks: `░░░░` (remaining)
- Percentage display: `[████████░░░░] 40%`

**Status Icons:**

- ✅ Success messages
- ⚠️ Warnings (production deployments, missing files)
- ℹ️ Informational messages
- ✗ Error messages
- → Progress indicators
- • List bullet points

**Color Coding:**

- Cyan: Headers, borders, progress bars
- Green: Success messages, checkmarks
- Yellow: Warnings
- Red: Errors
- Magenta: Highlights
- Dim: Secondary information

### Smart Recommendations (EntireStackFlow)

```text
┌─ 💡 Smart Recommendations ─────────────────────────────────────────
│ • Found Dockerfile but no images detected. Consider building image first:
│   'docker build -t myapp .'
│ • Found terraform/ directory. Consider initializing:
│   'cd terraform && terraform init && terraform plan -out=tfplan'
│ • Found GitHub Actions workflows. Consider CI/CD Security Audit workflow.
└────────────────────────────────────────────────────────────────────
```

### Production Warnings (DeploymentFlow)

When deploying to production, the wizard displays strict requirements:

```text
┌─ ⚠️  Production Deployment Requirements ───────────────────────────
│ • Deep scan profile (comprehensive checks)
│ • Zero CRITICAL findings
│ • Compliance validation (OWASP, CWE, PCI DSS)
│ • All container images scanned
│ • Infrastructure-as-Code validated
└────────────────────────────────────────────────────────────────────

⚠️  Production deployments require 'deep' profile (30-60 min)
```

### Profile Information (RepoFlow)

Clear profile comparison before selection:

```text
┌─ 📊 Profile Options ───────────────────────────────────────────────
│ • fast: 3 tools, 5-8 minutes (pre-commit, quick checks)
│ • balanced: 8 tools, 15-20 minutes (CI/CD, regular audits)
│ • deep: 12 tools, 30-60 minutes (security audits, compliance)
└────────────────────────────────────────────────────────────────────
```

### CI/CD Pipeline Detection (CICDFlow)

```text
┌─ 🔍 Detected CI/CD Pipelines ──────────────────────────────────────
│ • GitHub Actions workflows: 3 detected
│   → ci.yml
│   → release.yml
│   → security.yml
│ • Container images: 2 found in pipelines
└────────────────────────────────────────────────────────────────────

ℹ️  Recommended: 'fast' profile for CI/CD pipelines (5-8 minutes)
```

### Dependency Detection (DependencyFlow)

```text
┌─ 🔍 Detected Dependency Files ─────────────────────────────────────
│ • Package manifests: 3 detected
│   → requirements.txt
│   → package.json
│   → Cargo.toml
│ • Lock files: 2 detected (reproducible scans)
│   → poetry.lock
│   → package-lock.json
│ • Container images: 1 detected
└────────────────────────────────────────────────────────────────────
```

### Benefits

- **Improved UX:** Clear visual hierarchy with borders and icons
- **Real-time feedback:** Progress bars reduce uncertainty during long scans
- **Time estimates:** Users can plan workflow with accurate time predictions
- **Contextual guidance:** Smart recommendations based on detected files
- **Environment awareness:** Production vs staging warnings prevent mistakes
- **Accessibility:** Color-coded messages (green=success, yellow=warning, red=error)

---

## Five Workflow Types (v0.9.0+)

**NEW in v0.9.0:** The wizard now supports 5 specialized workflows tailored to different use cases. Each workflow auto-detects targets, provides smart recommendations, and generates workflow-specific artifacts.

### 1. Single Repository Scanning (RepoFlow)

**Use Case:** Scan a single repository for secrets, vulnerabilities, and code issues

**Auto-Detection:**

- Detects if current directory is a Git repository
- Detects programming language and package managers

**Example:**
```bash
jmotools wizard
# Select workflow: "Single Repository"
# Profile: balanced (recommended)
# Generates: Makefile with security-scan target
```

**Artifacts Generated:**

- Basic Makefile with `security-scan`, `security-report`, `security-clean` targets
- Optional GitHub Actions workflow
- Optional shell script

---

### 2. Entire Development Stack (EntireStackFlow)

**Use Case:** Scan everything in current directory (repos + containers + IaC + web apps)

**Auto-Detection:**

- All Git repositories
- Container images (from Dockerfile, docker-compose.yml, K8s manifests)
- IaC files (Terraform, CloudFormation, K8s)
- Web applications (from package.json, docker-compose ports)

**Smart Recommendations:**

- "Found Dockerfile → build image first: `docker build -t myapp .`"
- "Found terraform/ directory → initialize: `terraform init && terraform plan`"
- "Found .gitlab-ci.yml → scan GitLab repositories with `--gitlab-repo`"
- "Found kubernetes/ directory → scan live cluster with `--k8s-context`"
- "Found GitHub Actions workflows → consider CI/CD Security Audit"

**Example:**
```bash
jmotools wizard
# Select workflow: "Entire Development Stack"
# Profile: balanced
# Parallel scanning: yes
# Generate artifacts: yes
```

**Detected Output Example:**

```text
🔍 Detected targets:
  ✓ 3 repositories
  ✓ 2 container images (nginx:latest, postgres:14)
  ✓ 5 IaC files (Terraform)
  ✓ 1 web application (http://localhost:3000)

💡 Smart Recommendations:
  • Found Dockerfile for 'myapp' but image not built yet. Build it first: 'docker build -t myapp .'
  • Found .gitlab-ci.yml. Consider scanning GitLab repositories with '--gitlab-repo'.
```

**Artifacts Generated:**

- Comprehensive Makefile with 8 targets:
  - `security-scan-all` - Scan entire stack
  - `security-scan-repos` - Repositories only
  - `security-scan-images` - Images only
  - `security-scan-iac` - IaC files only
  - `security-scan-fast` - Quick scan (5-8 min)
  - `security-scan-deep` - Comprehensive (30-60 min)
  - `security-report` - Generate report
  - `security-clean` - Clean results
- Multi-target GitHub Actions workflow
- GitLab CI pipeline with 2 stages (scan + report)
- docker-compose.security.yml with scan + report services

---

### 3. CI/CD Security Audit (CICDFlow)

**Use Case:** Audit CI/CD pipeline security (GitHub Actions, GitLab CI, Jenkins)

**Auto-Detection:**

- CI pipeline files (.github/workflows/, .gitlab-ci.yml, Jenkinsfile)
- Container images referenced in pipelines
- Secrets in pipeline files

**Example:**
```bash
jmotools wizard
# Select workflow: "CI/CD Security Audit"
# Profile: fast (recommended for CI/CD)
# Scan pipeline files: yes
# Scan pipeline images: yes (2 images detected)
# Check GitHub Actions permissions: yes
```

**Artifacts Generated:**

- Makefile with 6 CI/CD-specific targets:
  - `security-audit-ci` - Full CI/CD audit
  - `security-audit-fast` - Fast check (for pipelines)
  - `security-check-pipelines` - Scan pipeline files for secrets
  - `security-check-images` - Scan container images from pipelines
  - `security-report` - Generate report
  - `security-clean` - Clean results
- GitHub Actions workflow with fail-on HIGH
- GitLab CI pipeline with audit stage
- docker-compose for CI audit

---

### 4. Pre-Deployment Checklist (DeploymentFlow)

**Use Case:** Run final security checks before deploying to production

**Auto-Detection:**

- Deployment targets (IaC, container images, K8s manifests)
- Environment (staging vs production) from:
  - Environment variables (ENVIRONMENT, NODE_ENV, etc.)
  - .env files
  - Kubernetes namespace declarations

**Environment-Aware Defaults:**

- **Staging:** balanced profile, fail on HIGH
- **Production:** deep profile, fail on CRITICAL

**Example:**
```bash
jmotools wizard
# Select workflow: "Pre-Deployment Checklist"
# Environment detected: production
#
# ⚠️  Production deployment requires:
#   • Deep scan profile (comprehensive checks)
#   • Zero CRITICAL findings
#   • Compliance validation (OWASP, CWE, PCI DSS)
#
# Profile: deep (recommended for production)
# Fail on: CRITICAL
```

**Artifacts Generated:**

- Makefile with deployment gates:
  - `security-check-staging` - Staging gate (fail on HIGH+)
  - `security-check-production` - Production gate (fail on CRITICAL)
  - `security-sbom` - Generate SBOM
  - `security-full-check` - Full pre-deployment scan
  - `security-report` - Generate report
- GitHub Actions workflow with manual deployment trigger
- GitLab CI pipeline with manual pre-deployment job
- docker-compose for pre-deployment checks

---

### 5. Dependency Security Audit (DependencyFlow)

**Use Case:** Focus on SBOM generation and dependency vulnerability scanning

**Auto-Detection:**

- Package manifests (14 types): Python, JavaScript, Go, Rust, Java, Ruby, .NET
- Lock files (9 types): poetry.lock, package-lock.json, yarn.lock, go.sum, etc.
- Container images (for SBOM extraction)

**Example:**
```bash
jmotools wizard
# Select workflow: "Dependency Security Audit"
#
# 🔍 Detected dependency files:
#   Package manifests:
#     • requirements.txt
#     • package.json
#   Lock files:
#     • poetry.lock
#     • package-lock.json
#   Container images: 2 detected
#
# Generate SBOM: yes
# Scan for vulnerabilities: yes
# Check licenses: no
```

**Artifacts Generated:**

- Basic Makefile with dependency-focused targets
- GitHub Actions workflow using syft + trivy
- GitLab CI pipeline for dependency scanning
- docker-compose for SBOM generation

---

### Choosing the Right Workflow

| Workflow | Best For | Time | Tools |
|----------|----------|------|-------|
| **Single Repository** | Individual repos, quick checks | 5-8 min (fast) | 3-8 tools |
| **Entire Stack** | Full development environment | 15-20 min | 8 tools |
| **CI/CD Audit** | Pipeline security validation | 5-10 min | 2-3 tools |
| **Pre-Deployment** | Production deployment gates | 15-30 min | 8-12 tools |
| **Dependency Audit** | SBOM + vulnerability focus | 5-10 min | 2 tools |

**Pro Tip:** Use `jmotools wizard` and select the workflow that matches your current task. The wizard will auto-detect targets and provide smart recommendations.

---

## Basic Interactive Mode

The wizard guides you through six steps to configure and run a security scan.

### Starting the Wizard

```bash
jmotools wizard
```

### Interactive Steps

#### Step 1: Select Scanning Profile

Choose from three profiles based on your needs:

- **fast** (2-5 minutes): Quick scan with core tools (trufflehog, semgrep, trivy)
- **balanced** (5-15 minutes): Comprehensive scan with all recommended tools
- **deep** (15-45 minutes): Exhaustive scan with all tools

#### Step 2: Select Execution Mode

Choose how to run the scan:

- **native**: Use locally installed security tools
- **docker**: Use pre-built Docker image (zero installation required)

The wizard automatically detects if Docker is installed and running.

#### Step 3a: Select Target Type (v0.6.2+)

Choose what type of asset to scan:

- **repo**: Repositories (local Git repos)
- **image**: Container images (Docker/OCI)
- **iac**: Infrastructure as Code (Terraform/CloudFormation/K8s)
- **url**: Web applications/APIs (DAST scanning)
- **gitlab**: GitLab repositories (with token)
- **k8s**: Kubernetes clusters (live clusters)

#### Step 3b: Configure Target

Based on the target type selected, configure specific details:

**For Repositories:**

- **repo**: Single repository
- **repos-dir**: Directory containing multiple repos
- **targets**: File listing repo paths
- **tsv**: Clone repos from TSV file

**For Container Images:**

- Single image name or batch file with image list

**For IaC Files:**

- File path (auto-detects Terraform/CloudFormation/K8s)

**For Web URLs:**

- Single URL or batch file with URL list
- URL validation with reachability check

**For GitLab:**

- GitLab URL, token, and repo/group selection

**For Kubernetes:**

- Context, namespace, or all namespaces
- Context validation with kubectl

#### Step 5: Advanced Configuration

Optionally customize:

- **Threads**: Parallelism level (default based on profile)
- **Timeout**: Per-tool timeout in seconds
- **Fail-on**: Severity threshold for CI/CD (CRITICAL, HIGH, MEDIUM)

#### Step 6: Review Configuration

Review your choices and confirm before execution.

#### Step 7: Execute Scan

The wizard generates and displays the command, then prompts for execution.

---

## Non-Interactive Mode

Use defaults for automated workflows or scripting.

### Quick Scan with Defaults

```bash
# Use balanced profile on current directory
jmotools wizard --yes
```

### With Custom Options

```bash
# Fast profile in Docker mode
jmotools wizard --yes --docker

# Specific directory
cd /path/to/repos
jmotools wizard --yes
```

**Note:** Non-interactive mode uses these defaults:

- Profile: balanced
- Target: current directory (repos-dir mode)
- Docker: enabled if available and running
- Results: `./results`

---

## Docker Mode (Zero Installation)

**✨ The wizard can use Docker for ZERO tool installation - perfect for Windows users!**

Benefits:

- ✅ **Zero setup:** No Python, git, or security tool installation required
- ✅ **Cross-platform:** Works identically on Linux, macOS, and Windows (WSL2)
- ✅ **Consistent results:** Same tool versions everywhere
- ✅ **Isolated:** Doesn't affect your host system
- ✅ **Beginner-friendly:** Wizard auto-detects Docker and recommends it

### Interactive Docker Mode

```bash
jmotools wizard
```

At Step 2, choose **docker** mode. The wizard will use `ghcr.io/jimmy058910/jmo-security:latest`.

### Force Docker Mode

```bash
jmotools wizard --docker
```

This skips the execution mode prompt and uses Docker directly (if available).

### Docker Mode Benefits

- Zero tool installation
- Consistent tool versions
- Portable across systems
- Immediate scanning capability

---

## Windows Docker Mode

**Recommended workflow for Windows users using WSL2 + Docker Desktop.**

### Prerequisites

1. **Install WSL2**
   ```powershell
   # Run in PowerShell as Administrator
   wsl --install
   ```

2. **Install Docker Desktop**
   - Download: [https://www.docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop)
   - Enable WSL2 backend in settings
   - Ensure Docker is running

### Running the Wizard on Windows

```bash
# Open WSL2 terminal (Ubuntu)
wsl

# Install JMo Security (if not already installed)
git clone https://github.com/jimmy058910/jmo-security-repo.git
cd jmo-security-repo
pip install -e .

# Run wizard with Docker auto-detection
jmotools wizard --docker

# Wizard will:
# 1. Detect Docker is available
# 2. Pull ghcr.io/jimmy058910/jmo-security:latest
# 3. Guide you through target selection
# 4. Run scan in Docker container
# 5. Auto-open results in Windows browser
```

### Windows-Specific Tips

**Scanning Windows Files:**

```bash
# Access Windows drives via /mnt/
cd /mnt/c/Users/YourName/Projects/my-repo
jmotools wizard --docker
```

**Opening Results:**

```bash
# After scan completes, open in Windows browser
explorer.exe results/summaries/dashboard.html

# Or use WSL default browser
wslview results/summaries/dashboard.html
```

**Performance Optimization:**

```bash
# Clone repos to WSL filesystem (2-3x faster)
cd ~
git clone https://github.com/your-org/your-repo.git
cd your-repo
jmotools wizard --docker

# AVOID: /mnt/c/ (Windows mount) - much slower
```

### Troubleshooting Windows

**"Docker not found" error:**

```bash
# Ensure Docker Desktop is running
# Check Docker is accessible from WSL2
docker --version

# If not working, enable WSL2 integration:
# Docker Desktop → Settings → Resources → WSL Integration
# Enable integration for your WSL2 distro
```

**"Permission denied" error:**

```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Log out and back in, or:
newgrp docker
```

**Slow scans on Windows:**

- ✅ **DO:** Clone repos to WSL2 filesystem (`~/repos`)
- ❌ **DON'T:** Scan Windows filesystem (`/mnt/c/`) - 2-3x slower

### Why WSL2 + Docker for Windows?

- ✅ **Full compatibility:** All 12 tools work (many don't on native Windows)
- ✅ **Zero native installs:** No Python/git/tools on Windows required
- ✅ **Linux performance:** Scans run at native Linux speed
- ✅ **Easy file access:** Access Windows files via `/mnt/c/Users/...`
- ✅ **Wizard integration:** Auto-detects Docker, one-click scanning

---

## Multi-Target Scanning (v0.6.2+)

The wizard now supports scanning 6 different target types beyond repositories.

### Container Image Scanning

Scan Docker/OCI container images for vulnerabilities:

```bash
jmotools wizard
```

**Steps:**

1. Choose **balanced** profile
2. Choose **docker** or **native** mode
3. Select target type: **image**
4. Enter image name: `nginx:latest` (or provide `images.txt` file)
5. Accept defaults for threads/timeout
6. Review and execute

**Generated Command:**

```bash
jmo scan --image nginx:latest --results-dir results --profile-name balanced --threads 4 --timeout 600
```

**Results:**

- Trivy vulnerability scan
- Syft SBOM generation
- Findings in `results/individual-images/nginx_latest/`

### Infrastructure as Code Scanning

Scan Terraform state files, CloudFormation templates, or K8s manifests:

```bash
jmotools wizard
```

**Steps:**

1. Choose **balanced** profile
2. Choose **native** mode (Checkov requires local install)
3. Select target type: **iac**
4. Enter file path: `./infrastructure.tfstate`
5. Wizard auto-detects: **Terraform** (from extension/content)
6. Review and execute

**Generated Command:**

```bash
jmo scan --terraform-state ./infrastructure.tfstate --results-dir results --profile-name balanced
```

**Supported IaC Types:**

- **Terraform**: `*.tf`, `*.tfstate`, `*.tfvars`
- **CloudFormation**: `*.yaml`, `*.yml`, `*.json` (with AWS resources)
- **Kubernetes**: `*.yaml`, `*.yml` (with K8s resources)

**Auto-Detection:**

The wizard automatically detects IaC type from:

- File extension (`.tfstate` → Terraform)
- File content (scans for `"terraform_version"`, `AWSTemplateFormatVersion`, `apiVersion: v1`)

### Web Application Scanning (DAST)

Scan live web applications and APIs:

```bash
jmotools wizard
```

**Steps:**

1. Choose **balanced** profile
2. Choose **docker** mode (ZAP works best in Docker)
3. Select target type: **url**
4. Enter URL: `https://example.com`
5. Wizard validates URL (HEAD request, 2s timeout)
6. Review and execute

**Generated Command:**

```bash
docker run --rm -v "$(pwd)/results:/results" ghcr.io/jimmy058910/jmo-security:latest \
  scan --url https://example.com --results /results --profile balanced
```

**URL Validation:**

The wizard checks if URLs are reachable before scanning:

- ✅ Reachable: Proceeds with scan
- ❌ Unreachable: Shows warning, allows override

**Batch URL Scanning:**

Create `urls.txt`:

```text
https://app.example.com
https://api.example.com
https://admin.example.com
```

Run wizard and select **file** option when prompted.

### GitLab Repository Scanning

Scan GitLab-hosted repositories with full tool suite:

```bash
jmotools wizard
```

**Steps:**

1. Choose **balanced** profile
2. Choose **native** or **docker** mode
3. Select target type: **gitlab**
4. GitLab URL: `https://gitlab.com` (default)
5. Token: Uses `$GITLAB_TOKEN` env var (or prompts)
6. Repo: `mygroup/myrepo` (or group: `mygroup`)
7. Review and execute

**Generated Command:**

```bash
export GITLAB_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxx
jmo scan --gitlab-repo mygroup/myrepo --gitlab-token $GITLAB_TOKEN --results-dir results
```

**Token Security:**

- Wizard prefers `GITLAB_TOKEN` environment variable
- Never stores tokens in config files
- Token auto-redacted in logs/output

**GitLab Group Scanning:**

Scan all repos in a GitLab group:

```bash
# Set token
export GITLAB_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxx

# Run wizard, select gitlab → group
jmotools wizard

# Enter group: myorg
```

Wizard discovers all repos in `myorg` and scans them.

### Kubernetes Cluster Scanning

Scan live Kubernetes clusters for security issues:

```bash
jmotools wizard
```

**Steps:**

1. Choose **balanced** profile
2. Choose **native** mode (requires kubectl)
3. Select target type: **k8s**
4. Enter context: `prod` (or use current context)
5. Namespace: `default` (or `--all-namespaces`)
6. Wizard validates context with kubectl
7. Review and execute

**Generated Command:**

```bash
jmo scan --k8s-context prod --k8s-namespace default --results-dir results
```

**Context Validation:**

The wizard validates Kubernetes context before scanning:

```bash
kubectl config get-contexts
kubectl config use-context prod
```

- ✅ Valid context: Proceeds
- ❌ Invalid context: Shows error, prompts to choose from available contexts

**Scanning All Namespaces:**

```bash
jmo scan --k8s-context prod --k8s-all-namespaces --results-dir results
```

Trivy scans all workloads across all namespaces.

### Multi-Target Combined Scanning

The wizard can configure scans across multiple target types in one command:

#### Example: Full Infrastructure Audit

Run wizard 6 times (once per target type), then combine commands:

```bash
# From wizard-generated commands
jmo scan \
  --repo ./backend \
  --image myapp:latest \
  --terraform-state infrastructure.tfstate \
  --url https://myapp.com \
  --gitlab-repo myorg/frontend \
  --k8s-context prod --k8s-namespace myapp \
  --results-dir ./comprehensive-audit
```

All findings deduplicated and aggregated to `comprehensive-audit/summaries/`.

---

## Privacy-First Telemetry (v0.7.0+)

JMo Security includes optional, anonymous usage analytics to help improve the tool. The wizard provides clear opt-in/opt-out prompts.

### Telemetry Opt-In Prompt

During first run, the wizard asks for telemetry consent:

```text
📊 Help improve JMo Security with anonymous usage analytics

We collect:
✅ Tool usage counts (which scanners you use)
✅ Scan durations and success rates
✅ Error types (no error messages)
✅ Profile selection (fast/balanced/deep)

We NEVER collect:
❌ Code content or file paths
❌ Findings or security issues
❌ IP addresses or hostnames
❌ Repository names or URLs

Full transparency: See docs/TELEMETRY.md

Enable telemetry? (y/N):
```

### Managing Telemetry

**Enable telemetry:**

```bash
jmo telemetry --enable
```

**Disable telemetry:**

```bash
jmo telemetry --disable
```

**Check current status:**

```bash
jmo telemetry --status
```

**View what's collected:**

```bash
# See complete transparency doc
cat docs/TELEMETRY.md

# View telemetry data before sending
cat ~/.jmo/telemetry/pending/*.json
```

### Newsletter Integration

The wizard may prompt for newsletter signup (optional, separate from telemetry):

```text
📬 Get security tips and updates (optional)

Subscribe to newsletter for:
🚀 New feature announcements
💡 Real-world security case studies & exclusive guides

Email (or press Enter to skip):
```

**Newsletter features:**

- 100% optional (completely separate from telemetry)
- No spam guarantee (announcements only)
- Unsubscribe anytime via email link
- Privacy-first (email never shared)

**Subscribe later:**

Visit [https://jmotools.com/subscribe.html](https://jmotools.com/subscribe.html)

### Non-Interactive Telemetry Handling

**Respect existing telemetry settings:**

```bash
# If user already opted in/out, wizard respects choice
jmotools wizard --yes
```

**Explicitly disable telemetry for automated workflows:**

```bash
jmo telemetry --disable
jmotools wizard --yes
```

**CI/CD environment (telemetry auto-disabled):**

Telemetry is automatically disabled when running in CI/CD environments:

- `CI=true` environment variable
- Running in Docker container
- Non-interactive terminal (no TTY)

```yaml
# GitHub Actions - telemetry auto-disabled
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - run: jmotools balanced --repos-dir .
        # Telemetry automatically disabled in CI
```

### Privacy Guarantees

1. **Anonymous**: No personally identifiable information
2. **Transparent**: Full documentation in [docs/TELEMETRY.md](../TELEMETRY.md)
3. **Optional**: Easy opt-out, disabled by default in CI
4. **Local control**: Data stored locally until sent
5. **No tracking**: No cookies, IP logging, or fingerprinting

For complete details, see [docs/TELEMETRY.md](../TELEMETRY.md).

---

## Artifact Generation

Generate reusable artifacts without running a scan.

### Generate Makefile Target

```bash
jmotools wizard --emit-make-target Makefile.security
```

**Output:**
```makefile
# JMo Security Scan Target (generated by wizard)
.PHONY: security-scan
security-scan:
  jmotools balanced --repos-dir /home/user/repos --results-dir results --threads 4 --timeout 600 --human-logs
```

**Usage:**
```bash
make -f Makefile.security security-scan
```

### Generate Shell Script

```bash
jmotools wizard --emit-script scan.sh
```

**Output:**
```bash
#!/usr/bin/env bash
# JMo Security Scan Script (generated by wizard)
set -euo pipefail

jmotools balanced --repos-dir /home/user/repos --results-dir results --threads 4 --timeout 600 --human-logs
```

**Usage:**
```bash
chmod +x scan.sh
./scan.sh
```

### Generate GitHub Actions Workflow

#### Native Mode

```bash
jmotools wizard --emit-gha .github/workflows/security.yml
```

**Output:**
```yaml
name: Security Scan
on:
  push:
    branches: [main]
  pull_request:
  schedule:

    - cron: '0 0 * * 0'  # Weekly

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:

      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install JMo Security
        run: pip install jmo-security

      - name: Install Security Tools
        run: |
          # Install based on profile: balanced
          # Tools: gitleaks, noseyparker, semgrep, syft, trivy, checkov, hadolint
          # See: https://github.com/jimmy058910/jmo-security-repo#tool-installation

      - name: Run Security Scan
        run: |
          jmotools balanced --repos-dir . --results-dir results \
            --threads 4 \
            --timeout 600

      - name: Upload Results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-results
          path: results/

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results/summaries/findings.sarif
```

#### Docker Mode Variant

```bash
jmotools wizard --docker --emit-gha .github/workflows/security-docker.yml
```

**Output:**
```yaml
name: Security Scan
on:
  push:
    branches: [main]
  pull_request:
  schedule:

    - cron: '0 0 * * 0'  # Weekly

jobs:
  security-scan:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/jimmy058910/jmo-security:latest
    steps:

      - uses: actions/checkout@v4

      - name: Run Security Scan
        run: |
          jmo scan --repo . --results results --profile balanced \
            --threads 4 \
            --timeout 600

      - name: Upload Results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-results
          path: results/

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results/summaries/findings.sarif
```

---

## Common Workflows

### First-Time User (No Tools Installed)

```bash
# Use Docker mode to avoid tool installation
jmotools wizard --docker
```

**Steps:**

1. Choose **balanced** profile (default)
2. Docker mode detected and enabled
3. Enter repos directory path
4. Accept defaults for threads/timeout
5. Review and confirm
6. Execute scan

### CI/CD Integration Setup

```bash
# Generate GitHub Actions workflow with HIGH threshold
jmotools wizard --emit-gha .github/workflows/security.yml
```

Then edit the generated workflow to add `--fail-on HIGH`:

```yaml

- name: Run Security Scan
  run: |
    jmotools balanced --repos-dir . --results-dir results \
      --threads 4 \
      --timeout 600 \
      --fail-on HIGH
```

### Weekly Scheduled Scans

1. Generate a shell script:

```bash
jmotools wizard --emit-script ~/weekly-scan.sh
```

2. Add to crontab:

```bash
crontab -e
```

```cron
# Run security scan every Sunday at 2 AM
0 2 * * 0 /home/user/weekly-scan.sh
```

### Multi-Repository Audit

1. Create a directory with repos:

```bash
mkdir ~/security-audit
cd ~/security-audit
git clone https://github.com/org/repo1.git
git clone https://github.com/org/repo2.git
git clone https://github.com/org/repo3.git
```

2. Run wizard:

```bash
jmotools wizard
```

3. Select:
   - Profile: **deep**
   - Mode: **native** or **docker**
   - Target: **repos-dir** → `/home/user/security-audit`
   - Threads: 2 (for deep scans)

### Clone from TSV and Scan

1. Create TSV file (`repos.tsv`):

```tsv
url  description
https://github.com/org/repo1.git  Main API
https://github.com/org/repo2.git  Frontend
https://github.com/org/repo3.git  Mobile app
```

2. Run wizard:

```bash
jmotools wizard
```

3. Select:
   - Profile: **balanced**
   - Mode: **docker** (recommended)
   - Target: **tsv** → `./repos.tsv`
   - Destination: `cloned-repos`

### Quick Validation Before Commit

```bash
# Fast scan on current repo
cd /path/to/my-repo
jmotools wizard --yes
```

Uses defaults:

- Profile: balanced
- Target: current directory
- Results: `./results`

Then check:

```bash
cat results/summaries/SUMMARY.md
open results/summaries/dashboard.html
```

---

## Tips and Tricks

### 1. Save Time with Non-Interactive Mode

If you're repeating scans with similar settings:

```bash
# Save the generated command from first run
jmotools wizard --yes 2>&1 | grep "jmotools balanced"

# Run directly next time
jmotools balanced --repos-dir ~/repos --results-dir results --threads 4 --timeout 600
```

### 2. Docker Mode for Clean Environments

Use Docker mode for:

- CI/CD pipelines (consistent environment)
- Testing new tool versions
- Avoiding local tool installation
- Running on different machines

### 3. Generate Artifacts for Team

Share generated artifacts with your team:

```bash
# Generate Makefile for team
jmotools wizard --emit-make-target Makefile.security
git add Makefile.security
git commit -m "Add security scan Makefile target"
```

Team members can then run:

```bash
make -f Makefile.security security-scan
```

### 4. Profile Selection Guide

- **fast**: Pre-commit hooks, quick validation (2-5 min)
- **balanced**: CI/CD pipelines, regular audits (5-15 min)
- **deep**: Weekly/monthly deep audits, compliance (15-45 min)

### 5. Severity Threshold for CI

Set `--fail-on` based on your security posture:

- `CRITICAL`: Only block on verified secrets
- `HIGH`: Block on likely secrets and serious vulnerabilities
- `MEDIUM`: Stricter gating for sensitive projects
- _(empty)_: Don't fail, just report (for monitoring)

---

## Troubleshooting

### Docker Not Found

If wizard shows "Docker not detected":

```bash
# Install Docker first
# See: https://docs.docker.com/get-docker/

# Verify installation
docker --version
docker info
```

### No Repositories Detected

If wizard warns "No git repositories detected" in repos-dir mode:

**Check:**

1. Path points to directory containing repos (not a single repo)
2. Each subdirectory has a `.git` folder

**Example correct structure:**

```text
~/my-repos/
├── repo1/
│   └── .git/
├── repo2/
│   └── .git/
└── repo3/
    └── .git/
```

### Wizard Cancelled

Press `Ctrl+C` at any time to cancel. The wizard is stateless and can be rerun.

---

## See Also

- [QUICKSTART.md](../../QUICKSTART.md) - Quick start guide
- [README.md](../../README.md) - Comprehensive documentation
- [DOCKER_README.md](../DOCKER_README.md) - Docker usage guide
- [github-actions-docker.yml](./github-actions-docker.yml) - GHA examples
