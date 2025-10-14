# Docker Quick Start for Beginners

**Complete step-by-step guide for running JMo Security Suite on a fresh computer.**

No security tools installation required - just Docker!

---

## Prerequisites

**You need:** A computer with Docker installed.

**Don't have Docker?** Follow the installation guide below for your operating system.

---

## Step 1: Install Docker (if not already installed)

### Windows

1. Download Docker Desktop from: <https://www.docker.com/products/docker-desktop>
2. Run the installer (`Docker Desktop Installer.exe`)
3. Follow the installation wizard (accept defaults)
4. Restart your computer when prompted
5. Open Docker Desktop and wait for it to start (green icon in taskbar)
6. Open PowerShell or Command Prompt to verify:
   ```powershell
   docker --version
   ```
   You should see: `Docker version XX.X.X`

### macOS

1. Download Docker Desktop from: <https://www.docker.com/products/docker-desktop>
2. Open the `.dmg` file and drag Docker to Applications
3. Launch Docker from Applications folder
4. Follow the setup wizard (accept defaults)
5. Wait for Docker to start (whale icon in menu bar)
6. Open Terminal and verify:
   ```bash
   docker --version
   ```
   You should see: `Docker version XX.X.X`

### Linux (Ubuntu/Debian)

1. Open Terminal and run:
   ```bash
   # Update package list
   sudo apt-get update

   # Install Docker
   sudo apt-get install -y docker.io

   # Add your user to docker group (so you don't need sudo)
   sudo usermod -aG docker $USER

   # Log out and log back in for group changes to take effect
   ```

2. After logging back in, verify:
   ```bash
   docker --version
   ```
   You should see: `Docker version XX.X.X`

---

## Step 2: Pull the JMo Security Image

This downloads the pre-built image with all security tools.

**Open your terminal** (Command Prompt/PowerShell on Windows, Terminal on Mac/Linux)

```bash
docker pull ghcr.io/jimmy058910/jmo-security:latest
```

**Expected output:**
```
latest: Pulling from jimmy058910/jmo-security
Digest: sha256:abc123...
Status: Downloaded newer image for ghcr.io/jimmy058910/jmo-security:latest
```

**Time:** 1-3 minutes (depending on internet speed)
**Size:** ~180MB compressed download, ~500MB uncompressed

**Note:** This is a one-time download. Future runs will be instant!

---

## Step 3: Scan Your First Project

### Option A: Scan the Current Directory (Recommended for Beginners)

1. Open terminal and navigate to your project folder:
   ```bash
   # Windows
   cd C:\Users\YourName\Projects\my-project

   # Mac/Linux
   cd ~/Projects/my-project
   ```

2. Run the scan:
   ```bash
   docker run --rm -v ${PWD}:/scan ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan --results /scan/results --profile balanced --human-logs
   ```

   **What this command does:**
   - `docker run --rm` - Run the container and remove it when done
   - `-v ${PWD}:/scan` - Mount your current directory into the container
   - `scan` - Run a security scan
   - `--repo /scan` - Scan the mounted directory
   - `--results /scan/results` - Save results to a "results" folder
   - `--profile balanced` - Use the default scanning profile
   - `--human-logs` - Show readable progress messages

3. **Wait for the scan to complete** (typically 1-5 minutes)

   You'll see output like:
   ```
   [INFO] Starting security scan...
   [INFO] Running gitleaks...
   [INFO] Running semgrep...
   [INFO] Running trivy...
   ...
   [INFO] Scan complete!
   ```

### Option B: Scan a Specific Folder

If you want to scan a different folder:

**Windows PowerShell:**
```powershell
docker run --rm -v "C:\Users\YourName\Projects\my-project:/scan" ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan --results /scan/results --profile balanced --human-logs
```

**Mac/Linux:**
```bash
docker run --rm -v "/Users/yourname/Projects/my-project:/scan" ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan --results /scan/results --profile balanced --human-logs
```

**Important:** Replace the path with your actual project path!

---

## Step 4: View Your Results

After the scan completes, you'll have a `results` folder in your project directory.

### Quick Summary

**Open this file in your browser:**
```
results/summaries/dashboard.html
```

This shows an interactive dashboard with:
- Total findings by severity
- Findings by tool
- Detailed list of all issues
- Filterable and sortable tables

### Detailed Report

**Read this file for details:**
```
results/summaries/SUMMARY.md
```

Example:
```markdown
# Security Scan Summary

## Overview
- Total Findings: 42
- Critical: 2
- High: 8
- Medium: 15
- Low: 12
- Info: 5

## Top Issues
1. Hardcoded API key detected in config.py (CRITICAL)
2. SQL injection vulnerability in user.py (HIGH)
3. Outdated dependency with known CVE (HIGH)
...
```

### All Results Files

The `results` folder contains:
```
results/
├── individual-repos/
│   └── my-project/
│       ├── gitleaks.json      # Secrets scan results
│       ├── semgrep.json       # SAST results
│       ├── trivy.json         # Vulnerability results
│       └── ...
└── summaries/
    ├── dashboard.html         # Interactive web dashboard
    ├── SUMMARY.md             # Text summary
    ├── findings.json          # Machine-readable results
    └── findings.sarif         # For GitHub/GitLab integration
```

---

## Common Scanning Scenarios

### Scenario 1: Quick Scan (Faster, Fewer Tools)

Use the `fast` profile for a quick check:

```bash
docker run --rm -v ${PWD}:/scan ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan --results /scan/results --profile fast --human-logs
```

**Time:** ~30-60 seconds
**Tools:** gitleaks, semgrep (secrets + basic SAST only)

### Scenario 2: Deep Scan (Comprehensive, All Tools)

Use the `deep` profile for maximum coverage:

```bash
docker run --rm -v ${PWD}:/scan ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan --results /scan/results --profile deep --human-logs
```

**Time:** 3-10 minutes
**Tools:** All 11+ security scanners

### Scenario 3: Scan Multiple Projects

To scan all projects in a folder:

```bash
# If ~/Projects contains multiple project folders
docker run --rm -v ~/Projects:/repos ghcr.io/jimmy058910/jmo-security:latest scan --repos-dir /repos --results /repos/security-results --profile balanced --human-logs
```

This scans every subfolder in `~/Projects`.

---

## Understanding Severity Levels

| Severity | Meaning | Action Required |
|----------|---------|-----------------|
| **CRITICAL** | Immediate security risk (e.g., hardcoded passwords, RCE vulnerabilities) | Fix immediately |
| **HIGH** | Serious security issue (e.g., SQL injection, XSS) | Fix within 1 week |
| **MEDIUM** | Moderate risk (e.g., weak crypto, missing auth checks) | Fix within 1 month |
| **LOW** | Minor issue (e.g., info disclosure, weak headers) | Fix when convenient |
| **INFO** | Informational (e.g., deprecated APIs, style issues) | Optional improvement |

---

## Troubleshooting

### Problem: "docker: command not found"

**Solution:** Docker is not installed or not in PATH.
- Windows: Restart after installing Docker Desktop
- Mac: Launch Docker Desktop from Applications
- Linux: Run `sudo systemctl start docker`

### Problem: "permission denied while trying to connect to Docker"

**Solution (Linux):** Add your user to the docker group:
```bash
sudo usermod -aG docker $USER
# Log out and log back in
```

**Solution (Windows/Mac):** Ensure Docker Desktop is running (icon in taskbar/menu bar)

### Problem: "docker: Cannot connect to the Docker daemon"

**Solution:** Start Docker Desktop or the Docker service:
- Windows/Mac: Launch Docker Desktop app
- Linux: `sudo systemctl start docker`

### Problem: Scan takes too long

**Solution 1:** Use the `fast` profile:
```bash
docker run --rm -v ${PWD}:/scan ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan --results /scan/results --profile fast --human-logs
```

**Solution 2:** Use the slim image (smaller, faster):
```bash
docker pull ghcr.io/jimmy058910/jmo-security:slim
docker run --rm -v ${PWD}:/scan ghcr.io/jimmy058910/jmo-security:slim scan --repo /scan --results /scan/results --profile fast --human-logs
```

### Problem: "invalid reference format" or path errors

**Solution:** Check your path formatting:

**Windows PowerShell - Use quotes and forward slashes:**
```powershell
docker run --rm -v "${PWD}:/scan" ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan --results /scan/results --profile balanced
```

**If `${PWD}` doesn't work, use the full path:**
```powershell
docker run --rm -v "C:/Users/YourName/Projects/my-project:/scan" ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan --results /scan/results --profile balanced
```

### Problem: No results folder created

**Check:**
1. Did the scan complete successfully? Look for `[INFO] Scan complete!`
2. Are you in the right directory? Run `ls` (Mac/Linux) or `dir` (Windows)
3. Try with `--allow-missing-tools` flag:
   ```bash
   docker run --rm -v ${PWD}:/scan ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan --results /scan/results --profile balanced --allow-missing-tools --human-logs
   ```

---

## Next Steps

### Option 1: Set Up Continuous Scanning (CI/CD)

Add automated scanning to your GitHub repository:

1. Create `.github/workflows/security-scan.yml`:
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
         - run: jmo scan --repo . --results results --profile balanced --human-logs
         - uses: actions/upload-artifact@v4
           if: always()
           with:
             name: security-results
             path: results/
   ```

2. Commit and push - scans run automatically on every push!

**More examples:** See [docs/examples/github-actions-docker.yml](github-actions-docker.yml)

### Option 2: Use Docker Compose for Repeated Scans

Create `docker-compose.yml` in your project:

```yaml
version: '3.8'
services:
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
```

Then run:
```bash
docker-compose run --rm scan
```

Much easier to remember!

### Option 3: Learn Advanced Features

- **Custom profiles:** Configure scan behavior in `jmo.yml`
- **Suppression files:** Ignore false positives with `jmo.suppress.yml`
- **CI gating:** Fail builds on HIGH+ findings with `--fail-on HIGH`
- **Multiple formats:** Export to SARIF, YAML, JSON for other tools

**Full documentation:** [docs/DOCKER_README.md](DOCKER_README.md)

---

## Cheat Sheet

### Quick Commands

```bash
# Pull latest image
docker pull ghcr.io/jimmy058910/jmo-security:latest

# Scan current directory
docker run --rm -v ${PWD}:/scan ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan --results /scan/results --profile balanced

# Fast scan
docker run --rm -v ${PWD}:/scan ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan --results /scan/results --profile fast

# Deep scan
docker run --rm -v ${PWD}:/scan ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan --results /scan/results --profile deep

# Show help
docker run --rm ghcr.io/jimmy058910/jmo-security:latest --help

# List available commands
docker run --rm ghcr.io/jimmy058910/jmo-security:latest scan --help
```

### Profile Comparison

| Profile | Time | Tools | Best For |
|---------|------|-------|----------|
| **fast** | 30-60s | 2 | Quick checks, pre-commit hooks |
| **balanced** | 2-5 min | 6-8 | Default, good coverage |
| **deep** | 5-10 min | 11+ | Comprehensive audits, releases |

### Image Variants

| Variant | Size | Use Case |
|---------|------|----------|
| **:latest** | 500MB | Full scanning (recommended) |
| **:slim** | 200MB | CI/CD pipelines |
| **:alpine** | 150MB | Resource-constrained environments |

---

## Summary

**You've learned to:**
1. ✅ Install Docker on your computer
2. ✅ Pull the JMo Security image
3. ✅ Run your first security scan
4. ✅ View and understand results
5. ✅ Troubleshoot common issues

**What's next?**
- Scan all your projects
- Set up automated scanning in CI/CD
- Share results with your team
- Fix the security issues found!

**Need help?**
- Documentation: <https://jmotools.com>
- Issues: <https://github.com/jimmy058910/jmo-security-repo/issues>
- Full Docker Guide: [docs/DOCKER_README.md](DOCKER_README.md)

---

**Happy Scanning! 🔒**
