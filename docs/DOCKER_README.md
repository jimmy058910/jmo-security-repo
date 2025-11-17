# Docker Guide - Complete Reference

**Zero-installation security scanning using Docker containers.**

All 11+ security tools pre-installed and ready to use. Perfect for beginners, CI/CD pipelines, and production environments.

---

## Table of Contents

- [Quick Start (Absolute Beginners)](#quick-start-absolute-beginners)
- [Image Variants](#image-variants)
- [Basic Usage](#basic-usage)
- [CI/CD Integration](#cicd-integration)
- [Advanced Configuration](#advanced-configuration)
- [Docker Compose](#docker-compose)
- [Trend Analysis with Docker](#trend-analysis-with-docker)
- [Troubleshooting](#troubleshooting)
- [Building Custom Images](#building-custom-images)
- [Security Considerations](#security-considerations)

---

## Quick Start (Absolute Beginners)

**Never used Docker or security scanners before? Follow these steps:**

### Step 1: Install Docker (One-Time Setup)

#### Windows

1. Download Docker Desktop: <https://www.docker.com/products/docker-desktop>
2. Run the installer and follow the wizard (accept defaults)
3. Restart your computer when prompted
4. Open Docker Desktop and wait for the green icon in taskbar
5. Verify in PowerShell or Command Prompt:

   ```powershell
   docker --version
   ```

   Expected: `Docker version XX.X.X`

#### macOS

1. Download Docker Desktop: <https://www.docker.com/products/docker-desktop>
2. Open the `.dmg` file and drag Docker to Applications
3. Launch Docker from Applications folder
4. Wait for Docker to start (whale icon in menu bar)
5. Verify in Terminal:

   ```bash
   docker --version
   ```

   Expected: `Docker version XX.X.X`

#### Linux (Ubuntu/Debian)

```bash
# Update package list
sudo apt-get update

# Install Docker
sudo apt-get install -y docker.io

# Add your user to docker group (avoid sudo)
sudo usermod -aG docker $USER

# Log out and log back in for changes to take effect
```

Verify after logging back in:

```bash
docker --version
```

Expected: `Docker version XX.X.X`

### Step 2: Pull the JMo Security Image (One-Time)

#### Registry Options

We publish to three Docker registries:

**Amazon ECR Public - Recommended for AWS Users:**

```bash
docker pull public.ecr.aws/m2d8u2k1/jmo-security:latest
```

- ✅ **Unlimited pulls** (no rate limits)
- ✅ **Best for AWS** (ECS/EKS native integration)
- ✅ **Faster pulls in AWS** (geographic distribution)
- ✅ **Multi-arch support** (amd64 + arm64)
- ✅ **Free for all users**

**GitHub Container Registry (GHCR) - Recommended for General Use:**

```bash
docker pull ghcr.io/jimmy058910/jmo-security:latest
```

- ✅ **Unlimited pulls** (no rate limits)
- ✅ **Best for CI/CD** (production-grade)
- ✅ **Multi-arch support** (amd64 + arm64)
- ✅ **Free for all users**

**Docker Hub - Available in v0.5.2+:**

```bash
docker pull jmogaming/jmo-security:latest
```

- ✅ **Traditional registry** (familiar to Docker users)
- ✅ **Higher discoverability** (appears in Docker Hub search)
- ⚠️ **Rate limits:** 200 pulls per 6 hours (free tier)

**Recommendation:**

- **AWS users:** Use ECR Public for faster pulls and native AWS integration
- **General users:** Use GHCR for unlimited pulls without rate limits
- **Docker Hub users:** Use Docker Hub for familiarity and discoverability

**Download info:**

- Time: 1-3 minutes (depending on internet speed)
- Size: ~180MB compressed, ~500MB uncompressed
- One-time download - future runs are instant!

### Step 3: Run Your First Scan

#### Scan Current Directory (Easiest)

```bash
# Navigate to your project
cd /path/to/your/project

# Run the scan (Linux/macOS/WSL - use quoted $(pwd))
# Option 1: ECR Public (recommended for AWS users)
docker run --rm -v "$(pwd):/scan" public.ecr.aws/m2d8u2k1/jmo-security:latest \
  scan --repo /scan --results-dir /scan/results --profile-name balanced --human-logs

# Option 2: GitHub Container Registry (recommended for general users)
docker run --rm -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results-dir /scan/results --profile-name balanced --human-logs
```

**What this command does:**

- `docker run` - Run a container
- `--rm` - Auto-remove container when done
- `-v "$(pwd):/scan"` - Mount current directory into container at `/scan` (quotes handle spaces in paths)
- `ghcr.io/jimmy058910/jmo-security:latest` - Our security image
- `scan` - Run a security scan
- `--repo /scan` - Scan the mounted directory
- `--results /scan/results` - Save results to `results` folder
- `--profile balanced` - Use default scanning profile (recommended)
- `--human-logs` - Show readable progress messages

#### Windows PowerShell (Use This Syntax)

```powershell
docker run --rm -v "${PWD}:/scan" ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan --results-dir /scan/results --profile-name balanced --human-logs
```

**Important:** Windows users must use `${PWD}` (with curly braces) and quotes.

#### Cross-Platform Quick Reference

| Platform | Volume Mount Syntax | Example |
|----------|---------------------|---------|
| **Linux/macOS/WSL/Git Bash** | `"$(pwd):/scan"` | `docker run -v "$(pwd):/scan" ...` |
| **Windows PowerShell 5.1+** | `"${PWD}:/scan"` | `docker run -v "${PWD}:/scan" ...` |
| **Windows CMD** | `"%CD%:/scan"` | `docker run -v "%CD%:/scan" ...` |

**Why quotes matter:** Paths with spaces (e.g., `C:\My Projects\`) will fail without quotes.

### Step 4: View Your Results

After the scan completes (typically 2-5 minutes), open the results:

**HTML Dashboard (Interactive):**

```bash
# macOS
open results/summaries/dashboard.html

# Linux
xdg-open results/summaries/dashboard.html

# Windows
start results\summaries\dashboard.html
```

**Text Summary:**

```bash
# macOS/Linux
cat results/summaries/SUMMARY.md

# Windows
type results\summaries\SUMMARY.md
```

**Results Structure:**

```text
results/
├── individual-repos/
│   └── your-project/
│       ├── trufflehog.json    # Verified secrets scan
│       ├── semgrep.json       # SAST results
│       ├── trivy.json         # Vulnerabilities
│       └── ...
└── summaries/
    ├── dashboard.html         # Interactive dashboard
    ├── SUMMARY.md             # Text summary
    ├── findings.json          # Machine-readable
    └── findings.sarif         # For GitHub/GitLab
```

### Understanding Severity Levels

| Severity | Meaning | Action Required |
|----------|---------|-----------------|
| **CRITICAL** | Immediate security risk (e.g., hardcoded passwords) | Fix immediately |
| **HIGH** | Serious issue (e.g., SQL injection, XSS) | Fix within 1 week |
| **MEDIUM** | Moderate risk (e.g., weak crypto) | Fix within 1 month |
| **LOW** | Minor issue (e.g., info disclosure) | Fix when convenient |
| **INFO** | Informational (e.g., deprecated APIs) | Optional improvement |

---

## Image Variants

### Quick Variant Selection

**Choose the right Docker image based on your use case:**

| Variant | Size | Scan Time | Use Case | Command |
|---------|------|-----------|----------|---------|
| **fast** | 502 MB | 5-10 min | Pre-commit hooks, PR gates | `docker run jmosecurity/jmo-security:fast ...` |
| **balanced** | 1.41 GB | 18-25 min | CI/CD pipelines | `docker run jmosecurity/jmo-security:balanced ...` |
| **slim** | 557 MB | 12-18 min | Cloud/K8s focused | `docker run jmosecurity/jmo-security:slim ...` |
| **full** (`:latest`) | 1.97 GB | 40-70 min | Complete audits | `docker run jmosecurity/jmo-security:latest ...` |

**Tool Distribution:**

- **fast (8 tools):** trufflehog, semgrep, trivy, checkov, checkov-cicd, hadolint, syft, osv-scanner
- **balanced (21 tools):** fast + prowler, kubescape, zap, nuclei, akto, cdxgen, scancode, gosec, grype, yara, bearer, horusec, dependency-check
- **slim (15 tools):** Cloud/Kubernetes focused subset
- **full (28 tools):** All scanners including noseyparker, semgrep-secrets, bandit, trivy-rbac, falco, afl++, mobsf, lynis

📖 **Complete tool breakdown:** [docs/DOCKER_VARIANTS_MASTER.md](DOCKER_VARIANTS_MASTER.md)

---

### Detailed Variant Information

Three optimized images for different needs (v0.6.1+ with multi-stage builds):

| Variant | Size (v0.6.1) | Size (v0.6.0) | Reduction | Tools | Best For |
|---------|---------------|---------------|-----------|-------|----------|
| **`:latest`** | ~1.7GB | ~2.3GB | 27% | 11+ scanners | Complete scanning, local development |
| **`:slim`** | ~900MB | ~1.5GB | 40% | 7 core scanners | CI/CD pipelines, faster pulls |
| **`:alpine`** | ~600MB | ~1.0GB | 41% | 7 core scanners | Minimal footprint, resource-constrained |

**v0.6.1 Optimizations (ROADMAP #1):**

- **Multi-stage builds:** Separate builder and runtime stages eliminate build tools (curl, wget, tar, build-essential, clang, llvm)
- **Layer caching cleanup:** Aggressive removal of apt cache, pip cache, and Python bytecode
- **Volume mounting support:** Use `-v trivy-cache:/root/.cache/trivy` for persistent Trivy DB caching (first scan downloads DB ~30-60s, subsequent scans use cached DB)

**Note:** Trivy database pre-download was intentionally removed (adds 800MB to image) in favor of volume caching approach for better size/performance trade-off.

### Tools Included

**Full (`:latest`):**

- **Secrets:** trufflehog (verified), noseyparker (deep profile)
- **SAST:** semgrep, bandit (deep profile)
- **SBOM+Vuln:** syft, trivy
- **IaC:** checkov
- **Dockerfile:** hadolint
- **DAST:** OWASP ZAP (balanced + deep)
- **Runtime Security:** Falco (deep profile)
- **Fuzzing:** AFL++ (deep profile)
- **Utilities:** shellcheck, shfmt, ruff

**Slim/Alpine (`:slim`, `:alpine`):**

- **Secrets:** trufflehog (verified secrets only)
- **SAST:** semgrep
- **SBOM+Vuln:** syft, trivy
- **IaC:** checkov
- **Dockerfile:** hadolint
- **DAST:** OWASP ZAP (balanced profile support)

### Choosing a Variant

```bash
# Full - Maximum coverage
docker pull ghcr.io/jimmy058910/jmo-security:latest

# Slim - Balanced for CI/CD
docker pull ghcr.io/jimmy058910/jmo-security:slim

# Alpine - Smallest size
docker pull ghcr.io/jimmy058910/jmo-security:alpine
```

---

## Basic Usage

### Common Scanning Scenarios

#### Fast Scan (Quick Check)

```bash
docker run --rm -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results /scan/results --profile fast --human-logs
```

**Time:** ~30-60 seconds
**Tools:** trufflehog, semgrep, trivy (3 tools)

#### Balanced Scan (Recommended Default)

```bash
docker run --rm -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results /scan/results --profile balanced --human-logs
```

**Time:** 2-5 minutes
**Tools:** trufflehog, semgrep, syft, trivy, checkov, hadolint, zap (7 tools)

#### Deep Scan (Comprehensive)

```bash
docker run --rm -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results /scan/results --profile deep --human-logs
```

**Time:** 5-15 minutes
**Tools:** All 11+ scanners

### Scan Multiple Projects

```bash
# If ~/projects contains multiple repos
docker run --rm -v ~/projects:/repos ghcr.io/jimmy058910/jmo-security:latest \
  scan --repos-dir /repos --results /repos/security-results --profile balanced --human-logs
```

### Scan with CI Gating

```bash
# Fail if HIGH or CRITICAL findings detected
docker run --rm -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:latest \
  ci --repo /scan --fail-on HIGH --profile
```

**Exit codes:**

- `0` - Success (no findings above threshold)
- `1` - Findings detected above threshold

---

## CI/CD Integration

### GitHub Actions

#### Basic Scan

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/jimmy058910/jmo-security:latest
    steps:

      - uses: actions/checkout@v4

      - name: Run Security Scan
        run: jmo ci --repo . --fail-on HIGH --profile

      - name: Upload Results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-results
          path: results/

      - name: Upload SARIF to GitHub Security
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results/summaries/findings.sarif
```

#### Scheduled Deep Scan

```yaml
name: Weekly Security Audit

on:
  schedule:

    - cron: '0 0 * * 0'  # Every Sunday at midnight

jobs:
  audit:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/jimmy058910/jmo-security:latest
    steps:

      - uses: actions/checkout@v4

      - name: Deep Scan
        run: jmo ci --repo . --profile deep

      - name: Upload Results
        uses: actions/upload-artifact@v4
        with:
          name: weekly-audit-results
          path: results/
```

#### Matrix Scanning (Multiple Repos)

```yaml
name: Multi-Repo Security

on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/jimmy058910/jmo-security:slim
    strategy:
      matrix:
        repo: [repo1, repo2, repo3]
    steps:

      - uses: actions/checkout@v4
        with:
          repository: ${{ matrix.repo }}

      - name: Scan ${{ matrix.repo }}
        run: jmo ci --repo . --fail-on HIGH
```

### GitLab CI

```yaml
security-scan:
  image: ghcr.io/jimmy058910/jmo-security:latest
  script:

    - jmo ci --repo . --fail-on HIGH --profile
  artifacts:
    reports:
      sast: results/summaries/findings.sarif
    paths:

      - results/
    when: always
    expire_in: 30 days
```

### Jenkins

```groovy
pipeline {
    agent {
        docker {
            image 'ghcr.io/jimmy058910/jmo-security:latest'
            args '-v $WORKSPACE:/scan'
        }
    }
    stages {
        stage('Security Scan') {
            steps {
                sh 'jmo ci --repo /scan --fail-on HIGH --profile'
            }
        }
        stage('Archive Results') {
            steps {
                archiveArtifacts artifacts: 'results/**/*', allowEmptyArchive: false
            }
        }
    }
}
```

---

## Advanced Configuration

### Custom Profiles with jmo.yml

Mount a custom configuration file:

```bash
# Create jmo.yml in your project
cat > jmo.yml <<EOF
default_profile: custom
profiles:
  custom:
    tools: [trufflehog, semgrep, trivy]
    timeout: 300
    threads: 8
per_tool:
  semgrep:
    flags: ["--exclude", "node_modules", "--exclude", "*.test.js"]
  trivy:
    flags: ["--severity", "HIGH,CRITICAL"]
  zap:
    flags: ["-config", "api.disablekey=true"]
EOF

# Run with custom profile
docker run --rm -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results /scan/results --profile-name custom --human-logs
```

### Trivy Database Caching (v0.6.1+)

**Optimize scan performance with persistent Trivy vulnerability database caching:**

```bash
# First scan: Downloads Trivy DB to named volume (~30-60s for initial download)
docker run --rm \
  -v "$(pwd):/scan" \
  -v trivy-cache:/root/.cache/trivy \
  ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --profile balanced

# Subsequent scans: Reuses cached DB (30-60s faster - no download!)
docker run --rm \
  -v "$(pwd):/scan" \
  -v trivy-cache:/root/.cache/trivy \
  ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --profile balanced
```

**Benefits:**

- **First scan:** Downloads Trivy DB (~30-60s one-time cost per volume)
- **Subsequent scans:** Cached DB persists across containers (30-60s faster, no download)
- **CI/CD:** Reuse cache across pipeline runs for consistent performance
- **Multi-project scans:** Share cache across different projects
- **Image size:** Keeps images smaller (Trivy DB adds 800MB if pre-downloaded)

**Cache Management:**

```bash
# List all Docker volumes
docker volume ls

# Inspect Trivy cache volume
docker volume inspect trivy-cache

# Remove cache to force fresh download (e.g., after long periods)
docker volume rm trivy-cache
```

**CI/CD Example (GitHub Actions):**

```yaml
- name: Run security scan with caching
  run: |
    docker run --rm \
      -v ${{ github.workspace }}:/scan \
      -v trivy-cache:/root/.cache/trivy \
      ghcr.io/jimmy058910/jmo-security:latest \
      ci --repo /scan --fail-on HIGH
```

### Suppression File

Create `jmo.suppress.yml` to ignore false positives:

```yaml
suppressions:

  - id: "fingerprint-id-here"
    reason: "False positive - test file"

  - ruleId: "G101"
    path: "tests/*"
    reason: "Test secrets excluded"
```

### Running as Non-Root User

```bash
# Run as current user to avoid permission issues
docker run --rm --user $(id -u):$(id -g) \
  -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results /scan/results --profile balanced
```

### Resource Limits

```bash
# Limit memory and CPU
docker run --rm \
  --memory="2g" \
  --cpus="2.0" \
  -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results /scan/results --profile balanced
```

---

## Docker Compose

Create `docker-compose.yml` in your project:

```yaml
version: '3.8'

services:
  # Basic scan
  scan:
    image: ghcr.io/jimmy058910/jmo-security:latest
    volumes:

      - .:/scan
    command:

      - scan
      - --repo
      - /scan
      - --results
      - /scan/results
      - --profile
      - balanced
      - --human-logs

  # CI mode with gating
  ci:
    image: ghcr.io/jimmy058910/jmo-security:latest
    volumes:

      - .:/scan
    command:

      - ci
      - --repo
      - /scan
      - --fail-on
      - HIGH
      - --profile

  # Fast scan with slim image
  fast:
    image: ghcr.io/jimmy058910/jmo-security:slim
    volumes:

      - .:/scan
    command:

      - scan
      - --repo
      - /scan
      - --results
      - /scan/results
      - --profile
      - fast
```

**Usage:**

```bash
# Run balanced scan
docker-compose run --rm scan

# Run CI mode
docker-compose run --rm ci

# Run fast scan
docker-compose run --rm fast
```

---

## Trend Analysis with Docker

**Track security improvements over time using persistent SQLite history database.**

JMo Security v1.0.0+ includes comprehensive trend analysis capabilities that work seamlessly in Docker with proper volume mounting. This enables historical tracking, regression detection, and developer attribution across container runs.

### Prerequisites

**CRITICAL: Volume persistence is REQUIRED for trend analysis.**

Trend analysis relies on a SQLite history database (`~/.jmo/history.db`) that must persist across container runs. Without volume mounting, each scan starts fresh with no historical data.

### Basic Trend Analysis Workflow

#### Step 1: Run First Scan with History Persistence

```bash
# Create persistent .jmo directory
mkdir -p ~/.jmo

# Run first scan (creates baseline in history database)
docker run --rm \
  -v "$(pwd):/scan" \
  -v ~/.jmo:/root/.jmo \
  ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results-dir /scan/results-baseline --profile-name balanced
```

**What this does:**

- `-v ~/.jmo:/root/.jmo` - Mounts persistent directory for SQLite database
- Scan results automatically saved to history database
- Database location: `~/.jmo/history.db`

#### Step 2: Make Code Changes and Run Second Scan

```bash
# After fixing some security issues
docker run --rm \
  -v "$(pwd):/scan" \
  -v ~/.jmo:/root/.jmo \
  ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results-dir /scan/results-current --profile-name balanced
```

#### Step 3: Analyze Trends

```bash
# View trend analysis for last 30 days
docker run --rm \
  -v ~/.jmo:/root/.jmo \
  ghcr.io/jimmy058910/jmo-security:latest \
  trends analyze --days 30 --format text
```

**Output includes:**

- Finding velocity (new findings per day)
- Remediation rate (fixes per day)
- Security score trends (0-100)
- Statistical significance (Mann-Kendall test, p < 0.05)

### Common Trend Commands

#### Show Recent Scan History

```bash
docker run --rm \
  -v ~/.jmo:/root/.jmo \
  ghcr.io/jimmy058910/jmo-security:latest \
  trends show --limit 10 --format text
```

#### Check for Regressions

```bash
# Detect new HIGH/CRITICAL findings in last 7 days
docker run --rm \
  -v ~/.jmo:/root/.jmo \
  ghcr.io/jimmy058910/jmo-security:latest \
  trends regressions --days 7 --format text
```

#### View Security Score

```bash
# Current security posture (0-100)
docker run --rm \
  -v ~/.jmo:/root/.jmo \
  ghcr.io/jimmy058910/jmo-security:latest \
  trends score --format text
```

#### Compare Two Scans

```bash
# Interactive diff between two scans
docker run --rm \
  -v ~/.jmo:/root/.jmo \
  -v "$(pwd)/results:/results" \
  ghcr.io/jimmy058910/jmo-security:latest \
  trends compare --scan-id-1 latest --scan-id-2 previous --format text
```

#### Developer Attribution (Requires .git Mount)

```bash
# See who fixed the most security issues
docker run --rm \
  -v "$(pwd):/scan" \
  -v "$(pwd)/.git:/scan/.git:ro" \
  -v ~/.jmo:/root/.jmo \
  ghcr.io/jimmy058910/jmo-security:latest \
  trends developers --limit 10 --format text
```

**Important:** Developer attribution requires mounting `.git` directory for git blame integration.

### Exporting Trend Reports

#### Export HTML Report (Interactive Dashboard)

```bash
docker run --rm \
  -v ~/.jmo:/root/.jmo \
  -v "$(pwd)/results:/results" \
  ghcr.io/jimmy058910/jmo-security:latest \
  trends export html --output /results/trends-report.html
```

**Features:**

- Interactive Chart.js visualizations
- Finding velocity charts
- Security score gauges
- Remediation rate sparklines
- Top remediators leaderboard

#### Export JSON Data (Machine-Readable)

```bash
docker run --rm \
  -v ~/.jmo:/root/.jmo \
  -v "$(pwd)/results:/results" \
  ghcr.io/jimmy058910/jmo-security:latest \
  trends export json --output /results/trends-data.json
```

#### Export CSV (Excel/BI Tools)

```bash
docker run --rm \
  -v ~/.jmo:/root/.jmo \
  -v "$(pwd)/results:/results" \
  ghcr.io/jimmy058910/jmo-security:latest \
  trends export csv --output /results/trends-data.csv
```

#### Export Prometheus Metrics

```bash
docker run --rm \
  -v ~/.jmo:/root/.jmo \
  -v "$(pwd)/results:/results" \
  ghcr.io/jimmy058910/jmo-security:latest \
  trends export prometheus --output /results/metrics.prom
```

**Metrics exposed:**

- `jmo_security_score` (0-100)
- `jmo_findings_total` (by severity)
- `jmo_remediation_rate` (fixes per day)
- `jmo_finding_velocity` (new findings per day)

### Docker Compose Workflow for Trends

**See `docker-compose.trends.yml` for comprehensive example.**

```bash
# Download docker-compose.trends.yml from repository
curl -O https://raw.githubusercontent.com/jimmy058910/jmo-security-repo/main/docker-compose.trends.yml

# Run baseline scan
docker compose -f docker-compose.trends.yml run scan-baseline

# Run current scan (after code changes)
docker compose -f docker-compose.trends.yml run scan-current

# Analyze trends
docker compose -f docker-compose.trends.yml run analyze-trends

# Export HTML report
docker compose -f docker-compose.trends.yml run export-html

# Check for regressions
docker compose -f docker-compose.trends.yml run check-regressions

# View developer attribution
docker compose -f docker-compose.trends.yml run developers
```

**Benefits of Docker Compose approach:**

- Named volumes for automatic persistence
- Service dependencies (scan → analyze → export)
- Consistent configuration across runs
- Easy integration with CI/CD pipelines

### CI/CD Integration with Trends

#### GitHub Actions Example

```yaml
name: Security Scan with Trends

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for git blame

      # Restore history database from cache
      - name: Restore history cache
        uses: actions/cache@v4
        with:
          path: .jmo
          key: jmo-history-${{ github.repository }}

      # Run scan with trend analysis
      - name: Run security scan
        run: |
          mkdir -p .jmo
          docker run --rm \
            -v ${{ github.workspace }}:/scan \
            -v ${{ github.workspace }}/.jmo:/root/.jmo \
            ghcr.io/jimmy058910/jmo-security:latest \
            scan --repo /scan --results-dir /scan/results --profile-name balanced

      # Check for regressions (fail if new HIGH/CRITICAL)
      - name: Check for regressions
        run: |
          docker run --rm \
            -v ${{ github.workspace }}/.jmo:/root/.jmo \
            ghcr.io/jimmy058910/jmo-security:latest \
            trends regressions --format terminal

      # Export trend report
      - name: Export trend report
        run: |
          docker run --rm \
            -v ${{ github.workspace }}/.jmo:/root/.jmo \
            -v ${{ github.workspace }}/results:/results \
            ghcr.io/jimmy058910/jmo-security:latest \
            trends analyze --export html --export-file /results/trends-report.html

      # Upload reports
      - name: Upload trend report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-trends
          path: results/trends-report.html
```

**Key points:**

- Use `actions/cache` to persist `.jmo` directory across runs
- Cache key tied to repository (separate history per project)
- Full git history (`fetch-depth: 0`) enables developer attribution
- Regression checks can gate deployments

#### GitLab CI Example

```yaml
security-scan-with-trends:
  image: docker:latest
  services:
    - docker:dind
  variables:
    DOCKER_DRIVER: overlay2
  cache:
    key: jmo-history-${CI_PROJECT_ID}
    paths:
      - .jmo/
  script:
    - mkdir -p .jmo
    # Run scan
    - |
      docker run --rm \
        -v $PWD:/scan \
        -v $PWD/.jmo:/root/.jmo \
        ghcr.io/jimmy058910/jmo-security:latest \
        scan --repo /scan --results-dir /scan/results --profile-name balanced
    # Check regressions
    - |
      docker run --rm \
        -v $PWD/.jmo:/root/.jmo \
        ghcr.io/jimmy058910/jmo-security:latest \
        trends regressions --format terminal
    # Export HTML report
    - |
      docker run --rm \
        -v $PWD/.jmo:/root/.jmo \
        -v $PWD/results:/results \
        ghcr.io/jimmy058910/jmo-security:latest \
        trends analyze --export html --export-file /results/trends-report.html
  artifacts:
    paths:
      - results/trends-report.html
    expire_in: 30 days
```

**Key points:**

- Cache `.jmo` directory with project-specific key
- DinD (Docker-in-Docker) service for nested containers
- Artifacts persist trend reports for review

### Environment Variable Configuration

Override default behavior with environment variables:

```bash
docker run --rm \
  -v "$(pwd):/scan" \
  -v ~/.jmo:/root/.jmo \
  -e JMO_HISTORY_DB_PATH=/root/.jmo/custom-history.db \
  -e JMO_LOG_LEVEL=DEBUG \
  ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --profile-name balanced
```

**Configuration precedence:**

1. Environment variables (highest priority)
2. Mounted config files (`jmo.yml`)
3. Default values

### Troubleshooting Trends in Docker

#### "No scans found in history database"

**Problem:** Volume not mounted or database empty

**Solutions:**

1. Verify volume mount: `docker run --rm -v ~/.jmo:/root/.jmo ...`
2. Check database exists: `ls -lh ~/.jmo/history.db`
3. Run at least one scan first to populate database

#### "Permission denied" on .jmo directory

**Problem:** Container can't write to volume

**Solutions:**

```bash
# Fix permissions
chmod 755 ~/.jmo

# Run as current user
docker run --rm --user $(id -u):$(id -g) \
  -v ~/.jmo:/root/.jmo ...
```

#### "Git repository not found" for developer attribution

**Problem:** `.git` directory not mounted

**Solution:**

```bash
# Mount .git directory (read-only for safety)
docker run --rm \
  -v "$(pwd):/scan" \
  -v "$(pwd)/.git:/scan/.git:ro" \
  -v ~/.jmo:/root/.jmo \
  ghcr.io/jimmy058910/jmo-security:latest \
  trends developers --limit 10
```

#### Trend data persists after removing container

**Expected behavior:** This is by design!

Named volumes and bind mounts persist data intentionally. To reset:

```bash
# Remove history database
rm ~/.jmo/history.db

# Or remove entire .jmo directory
rm -rf ~/.jmo
```

#### Cache not working in CI/CD

**Solutions:**

1. **GitHub Actions:** Use `actions/cache` with consistent key
2. **GitLab CI:** Ensure cache key is project-specific
3. **Jenkins:** Use Docker volumes or bind mounts in pipeline

**See `docker-compose.trends.yml` for complete working examples.**

---

## Troubleshooting

### Common Issues

#### "docker: command not found"

**Problem:** Docker is not installed or not in PATH

**Solution:**

- **Windows/macOS:** Launch Docker Desktop application
- **Linux:** Start Docker service: `sudo systemctl start docker`
- Verify: `docker --version`

#### "permission denied while trying to connect to Docker daemon"

**Problem:** User doesn't have Docker permissions

**Solution (Linux):**

```bash
sudo usermod -aG docker $USER
# Log out and log back in
```

**Solution (Windows/macOS):**

- Ensure Docker Desktop is running (check system tray/menu bar)

#### "Cannot connect to the Docker daemon"

**Problem:** Docker daemon not running

**Solution:**

- **Windows/macOS:** Launch Docker Desktop app
- **Linux:** `sudo systemctl start docker`

#### Scan takes too long

**Solution 1:** Use faster profile

```bash
docker run --rm -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:slim \
  scan --repo /scan --results /scan/results --profile fast
```

**Solution 2:** Increase threads

```bash
# Add custom jmo.yml with more threads
echo "threads: 8" > jmo.yml
```

#### "invalid reference format" or path errors (Windows)

**Problem:** Path formatting issues

**Solution:** Use full path with forward slashes and quotes:

```powershell
docker run --rm -v "C:/Users/YourName/project:/scan" ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan --results /scan/results --profile balanced
```

#### Results folder not created

**Check:**

1. Scan completed successfully? Look for final success message
2. In correct directory? Run `pwd` (macOS/Linux) or `cd` (Windows)
3. Try with `--allow-missing-tools` flag:

   ```bash
   docker run --rm -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:latest \
     scan --repo /scan --results /scan/results --profile balanced --allow-missing-tools
   ```

#### Permission errors on results files

**Problem:** Container created files as root

**Solution:** Run as current user:

```bash
docker run --rm --user $(id -u):$(id -g) \
  -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results /scan/results --profile balanced
```

---

## Building Custom Images

### Custom Dockerfile

```dockerfile
FROM ghcr.io/jimmy058910/jmo-security:latest

# Add custom tools
RUN pip install my-custom-scanner

# Add custom configuration
COPY my-jmo.yml /app/jmo.yml

# Add custom scripts
COPY my-scripts/ /app/scripts/
```

Build:

```bash
docker build -t my-custom-security:latest .
```

### Using Different Base

```dockerfile
FROM ghcr.io/jimmy058910/jmo-security:slim

# Add only specific tools you need
RUN pip install bandit==1.7.5
```

---

## Security Considerations

### Image Security

**Practices we follow:**

- Official base images (Ubuntu 22.04, Alpine 3.18)
- Pinned tool versions (reproducible builds)
- Trivy scanning in CI (gate on HIGH/CRITICAL)
- SBOM generation (transparency)
- Provenance attestations (supply chain security)

### Runtime Security Best Practices

**1. Run as non-root:**

```bash
docker run --rm --user $(id -u):$(id -g) ...
```

**2. Use read-only volumes when possible:**

```bash
docker run --rm -v "$(pwd):/scan":ro ...
```

**3. Limit network access for untrusted repos:**

```bash
docker run --rm --network none ...
```

**4. Use resource limits:**

```bash
docker run --rm --memory="2g" --cpus="2.0" ...
```

### Verifying Images

**Check image digest:**

```bash
docker pull ghcr.io/jimmy058910/jmo-security:latest
docker inspect ghcr.io/jimmy058910/jmo-security:latest | grep -A 3 RepoDigests
```

**Scan image for vulnerabilities:**

```bash
docker run --rm aquasec/trivy image ghcr.io/jimmy058910/jmo-security:latest
```

---

## Additional Resources

- **Main Documentation:** [README.md](../README.md)
- **Quick Start Guide:** [QUICKSTART.md](../QUICKSTART.md)
- **User Guide:** [USER_GUIDE.md](USER_GUIDE.md)
- **Wizard Examples:** [examples/wizard-examples.md](examples/wizard-examples.md)
- **GitHub Actions Examples:** [examples/github-actions-docker.yml](examples/github-actions-docker.yml)
- **GitHub Container Registry (Primary):** <https://ghcr.io/jimmy058910/jmo-security>
- **Docker Hub (Available v0.5.2+):** <https://hub.docker.com/r/jmogaming/jmo-security>

---

## 📬 Stay Updated

**Get security tips and updates delivered to your inbox:**

[![Newsletter](https://img.shields.io/badge/📧_Newsletter-Subscribe-667eea)](https://jmotools.com/subscribe.html)
[![Ko-fi](https://img.shields.io/badge/💚_Ko--fi-Support-ff5e5b?logo=ko-fi&logoColor=white)](https://ko-fi.com/jmogaming)

- 🚀 New feature announcements
- 🔒 Weekly security best practices
- 💡 Real-world security case studies
- 🎁 Exclusive guides and early access

**[Subscribe to Newsletter](https://jmotools.com/subscribe.html)** | **[Support Full-Time Development](https://ko-fi.com/jmogaming)**

---

## Support

- **Issues:** <https://github.com/jimmy058910/jmo-security-repo/issues>
- **Discussions:** <https://github.com/jimmy058910/jmo-security-repo/discussions>
- **Email:** <general@jmogaming.com>
- **Website:** <https://jmotools.com>

---

Happy Scanning! 🔒
