# Quick Start - JMo Security

**v1.0.0** | Get scanning in 5 minutes.

---

## Prerequisites

- **Docker** (recommended) OR **Python 3.12+**
- **Git** (for repository scanning)

---

## Installation (Choose One)

### Option 1: Package Managers (30 seconds)

> **Note:** Homebrew and WinGet packages are planned for a future release. See [docs/MANUAL_INSTALLATION.md](docs/MANUAL_INSTALLATION.md) for current installation methods, or use pip/Docker below.

**macOS / Linux (coming soon):**

```bash
brew install jmo-security
jmo wizard
```

**Windows (coming soon):**

```powershell
winget install jmo.jmo-security
jmo wizard
```

---

### Option 2: Docker (60 seconds)

**No tool installation required - all 28 scanners included.**

```bash
# Pull image (one-time)
docker pull ghcr.io/jimmy058910/jmo-security:latest

# Scan current directory
docker run --rm -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results-dir /scan/results --profile balanced --human-logs
```

**Platform-specific volume syntax:**

| Platform | Syntax |
|----------|--------|
| Linux/macOS/WSL | `"$(pwd):/scan"` |
| Windows PowerShell | `"${PWD}:/scan"` |
| Windows CMD | `"%CD%:/scan"` |

**Image variants:**

| Variant | Tools | Size | Use Case |
|---------|-------|------|----------|
| `fast` | 9 | 502 MB | CI/CD gates, pre-commit |
| `slim` | 14 | 557 MB | Cloud/IaC, AWS/Azure/GCP/K8s |
| `balanced` | 18 | 1.4 GB | Production pipelines |
| `deep` | 28 | 2.0 GB | Complete audits |

**Complete guide:** [docs/DOCKER_README.md](docs/DOCKER_README.md)

---

### Option 3: pip install (5 minutes)

```bash
# Install JMo Security
pip install jmo-security

# Verify installation
jmo --help

# Check which tools are installed
jmo tools check --profile balanced

# Install missing tools (cross-platform)
jmo tools install --profile balanced

# Verify tools are ready
jmo tools check --profile balanced
```

**For contributing/development:** [CONTRIBUTING.md](CONTRIBUTING.md)

---

## First Scan

### Interactive Wizard (Recommended for Beginners)

```bash
jmo wizard
```

The wizard guides you through:

- Profile selection (fast/slim/balanced/deep)
- **Tool pre-flight check** (detects missing/outdated tools, offers to install)
- Target discovery (repos, images, URLs)
- Docker vs native mode
- Command preview before execution

**Non-interactive:** `jmo wizard --yes`

---

### Quick Commands

**Scan a repository:**

```bash
jmo scan --repo /path/to/repo --profile balanced --human-logs
```

**Scan a directory of repos:**

```bash
jmo scan --repos-dir ~/repos --profile balanced --human-logs
```

**Scan a container image:**

```bash
jmo scan --image nginx:latest --results-dir ./image-scan
```

**CI mode (scan + gate on severity):**

```bash
jmo ci --repo . --fail-on HIGH --profile balanced
```

---

### Scan Profiles

| Profile | Tools | Time | Use Case |
|---------|-------|------|----------|
| `fast` | 9 | 5-10 min | Pre-commit, PR validation |
| `slim` | 14 | 12-18 min | Cloud/IaC, AWS/Azure/GCP/K8s |
| `balanced` | 18 | 18-25 min | CI/CD pipelines |
| `deep` | 28 | 40-70 min | Full security audits |

---

## View Results

After scanning, results are in `results/summaries/`:

```bash
# Quick text summary
cat results/summaries/SUMMARY.md

# Interactive dashboard
open results/summaries/dashboard.html     # macOS
xdg-open results/summaries/dashboard.html # Linux
start results\summaries\dashboard.html    # Windows
```

**Output files:**

| File | Purpose |
|------|---------|
| `dashboard.html` | Interactive visual dashboard |
| `SUMMARY.md` | Human-readable overview |
| `findings.json` | Machine-readable findings (CommonFinding schema v1.2.0) |
| `findings.sarif` | GitHub/GitLab Code Scanning |

---

## Understanding Severity

| Severity | Action | Timeframe |
|----------|--------|-----------|
| **CRITICAL** | Fix immediately | 24 hours |
| **HIGH** | Fix soon | 1 week |
| **MEDIUM** | Schedule fix | 1 month |
| **LOW** | When convenient | Next quarter |

**Detailed guide:** [docs/RESULTS_GUIDE.md](docs/RESULTS_GUIDE.md)

---

## Multi-Target Scanning

Scan beyond repositories - 6 target types supported:

```bash
# Container image
jmo scan --image nginx:latest

# Terraform/IaC
jmo scan --terraform-state terraform.tfstate

# Live web app (DAST)
jmo scan --url https://example.com --tools zap

# Kubernetes cluster
jmo scan --k8s-context prod --k8s-all-namespaces

# GitLab repos
jmo scan --gitlab-group myorg --gitlab-token $TOKEN

# Everything together
jmo scan --repo . --image myapp:latest --url https://myapp.com
```

**Complete guide:** [docs/USER_GUIDE.md#multi-target-scanning](docs/USER_GUIDE.md#multi-target-scanning)

---

## What's Next

### Learn More

| Topic | Guide |
|-------|-------|
| Full CLI reference | [docs/USER_GUIDE.md](docs/USER_GUIDE.md) |
| Understanding results | [docs/RESULTS_GUIDE.md](docs/RESULTS_GUIDE.md) |
| Docker deep-dive | [docs/DOCKER_README.md](docs/DOCKER_README.md) |
| Platform setup | [docs/MANUAL_INSTALLATION.md](docs/MANUAL_INSTALLATION.md) |

### Key Features

| Feature | Guide |
|---------|-------|
| Tool management | [docs/USER_GUIDE.md#tool-management](docs/USER_GUIDE.md#tool-management) |
| Compare scans | [docs/USER_GUIDE.md#jmo-diff](docs/USER_GUIDE.md#jmo-diff) |
| Track trends | [docs/USER_GUIDE.md#jmo-trends](docs/USER_GUIDE.md#jmo-trends) |
| Scan history | [docs/USER_GUIDE.md#jmo-history](docs/USER_GUIDE.md#jmo-history) |
| Scheduled scans | [docs/SCHEDULE_GUIDE.md](docs/SCHEDULE_GUIDE.md) |
| AI remediation | [docs/MCP_SETUP.md](docs/MCP_SETUP.md) |
| Policy-as-code | [docs/POLICY_AS_CODE.md](docs/POLICY_AS_CODE.md) |

### For Contributors

| Topic | Guide |
|-------|-------|
| Development setup | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Testing | [TEST.md](TEST.md) |
| Release process | [docs/RELEASE.md](docs/RELEASE.md) |

---

## Troubleshooting

### Tools not found

```bash
# Check tool status for your profile
jmo tools check --profile balanced

# Install missing tools (cross-platform)
jmo tools install --profile balanced

# Or generate install script to review
jmo tools install --print-script > install-tools.sh
```

### Tools outdated

```bash
# Show outdated tools
jmo tools outdated

# Update all outdated tools
jmo tools update

# Update only critical security tools
jmo tools update --critical-only
```

### Permission denied

```bash
find scripts -type f -name "*.sh" -exec chmod +x {} +
```

### More help

- [CONTRIBUTING.md#ci-troubleshooting](CONTRIBUTING.md#ci-troubleshooting) - CI/CD issues
- [docs/MANUAL_INSTALLATION.md](docs/MANUAL_INSTALLATION.md) - Platform-specific issues
- [GitHub Issues](https://github.com/jimmy058910/jmo-security-repo/issues)

---

## Support

- **Ko-fi:** <https://ko-fi.com/jmogaming>
- **GitHub Sponsors:** <https://github.com/sponsors/jimmy058910>
- **Newsletter:** <https://jmotools.com/subscribe.html>

---

**Last Updated:** February 2026
