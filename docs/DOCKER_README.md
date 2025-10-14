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

```bash
docker pull ghcr.io/jimmy058910/jmo-security:latest
```

**Download info:**

- Time: 1-3 minutes (depending on internet speed)
- Size: ~180MB compressed, ~500MB uncompressed
- One-time download - future runs are instant!

### Step 3: Run Your First Scan

#### Scan Current Directory (Easiest)

```bash
# Navigate to your project
cd /path/to/your/project

# Run the scan
docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results /scan/results --profile balanced --human-logs
```

**What this command does:**

- `docker run` - Run a container
- `--rm` - Auto-remove container when done
- `-v $(pwd):/scan` - Mount current directory into container at `/scan`
- `ghcr.io/jimmy058910/jmo-security:latest` - Our security image
- `scan` - Run a security scan
- `--repo /scan` - Scan the mounted directory
- `--results /scan/results` - Save results to `results` folder
- `--profile balanced` - Use default scanning profile (recommended)
- `--human-logs` - Show readable progress messages

#### Windows PowerShell (Use This Syntax)

```powershell
docker run --rm -v "${PWD}:/scan" ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan --results /scan/results --profile balanced --human-logs
```

**Important:** Windows users must use `${PWD}` (with curly braces) and quotes.

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
│       ├── gitleaks.json      # Secrets scan
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

Three optimized images for different needs:

| Variant | Size | Tools | Best For |
|---------|------|-------|----------|
| **`:latest`** | ~500MB | 11+ scanners | Complete scanning, local development |
| **`:slim`** | ~200MB | 6 core scanners | CI/CD pipelines, faster pulls |
| **`:alpine`** | ~150MB | 6 core scanners | Minimal footprint, resource-constrained |

### Tools Included

**Full (`:latest`):**

- **Secrets:** gitleaks, trufflehog, noseyparker
- **SAST:** semgrep, bandit
- **SBOM+Vuln:** syft, trivy, osv-scanner
- **IaC:** checkov, tfsec
- **Dockerfile:** hadolint
- **Utilities:** shellcheck, shfmt, ruff

**Slim/Alpine (`:slim`, `:alpine`):**

- **Secrets:** gitleaks
- **SAST:** semgrep
- **SBOM+Vuln:** syft, trivy
- **IaC:** checkov
- **Dockerfile:** hadolint

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
docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results /scan/results --profile fast --human-logs
```

**Time:** ~30-60 seconds
**Tools:** gitleaks, semgrep only

#### Balanced Scan (Recommended Default)

```bash
docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results /scan/results --profile balanced --human-logs
```

**Time:** 2-5 minutes
**Tools:** All 7 core scanners

#### Deep Scan (Comprehensive)

```bash
docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest \
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
docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest \
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
    tools: [gitleaks, semgrep, trivy]
    timeout: 300
    threads: 8
per_tool:
  semgrep:
    flags: ["--exclude", "node_modules", "--exclude", "*.test.js"]
  trivy:
    flags: ["--severity", "HIGH,CRITICAL"]
EOF

# Run with custom profile
docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results /scan/results --profile-name custom --human-logs
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
  -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results /scan/results --profile balanced
```

### Resource Limits

```bash
# Limit memory and CPU
docker run --rm \
  --memory="2g" \
  --cpus="2.0" \
  -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest \
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
docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:slim \
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
   docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest \
     scan --repo /scan --results /scan/results --profile balanced --allow-missing-tools
   ```

#### Permission errors on results files

**Problem:** Container created files as root

**Solution:** Run as current user:

```bash
docker run --rm --user $(id -u):$(id -g) \
  -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest \
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
docker run --rm -v $(pwd):/scan:ro ...
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
- **Docker Hub:** Coming soon
- **GitHub Container Registry:** <https://ghcr.io/jimmy058910/jmo-security>

---

## Support

- **Issues:** <https://github.com/jimmy058910/jmo-security-repo/issues>
- **Discussions:** <https://github.com/jimmy058910/jmo-security-repo/discussions>
- **Email:** <general@jmogaming.com>
- **Website:** <https://jmotools.com>

---

Happy Scanning! 🔒
