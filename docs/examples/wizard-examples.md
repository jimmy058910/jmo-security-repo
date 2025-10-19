# Interactive Wizard Examples

The JMo Security Wizard provides a guided, interactive experience for beginners to perform security scans without needing to know command-line flags.

> **🪟 Windows Users:** The wizard automatically detects Docker and recommends Docker mode for the best experience. WSL2 + Docker Desktop provides zero-installation scanning with full tool compatibility. See [Windows Setup](#windows-docker-mode) below.

## Table of Contents

- [Basic Interactive Mode](#basic-interactive-mode)
- [Non-Interactive Mode](#non-interactive-mode)
- [Docker Mode (Zero Installation)](#docker-mode-zero-installation)
- [Windows Docker Mode](#windows-docker-mode)
- [Multi-Target Scanning (v0.6.2+)](#multi-target-scanning-v062)
- [Artifact Generation](#artifact-generation)
- [Common Workflows](#common-workflows)

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
