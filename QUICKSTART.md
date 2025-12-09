# Quick Start - JMo Security

**Get scanning in 5 minutes.**

---

## Prerequisites

- **Docker** (recommended) OR **Python 3.10+**
- **Git** (for repository scanning)

---

## Installation (Choose One)

### Option 1: Package Managers (30 seconds)

**macOS / Linux:**

```bash
brew install jmo-security
jmotools wizard
```

**Windows:**

```powershell
winget install jmo.jmo-security
jmotools wizard
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

| Variant | Size | Use Case |
|---------|------|----------|
| `fast` | 502 MB | CI/CD gates, pre-commit |
| `balanced` | 1.4 GB | Production pipelines |
| `slim` | 557 MB | Cloud/IaC focused |
| `full` | 2.0 GB | Complete audits |

**Complete guide:** [docs/DOCKER_README.md](docs/DOCKER_README.md)

---

### Option 3: pip install (5 minutes)

```bash
# Install JMo Security
pip install jmo-security

# Verify installation
jmo --help
jmotools --help

# Optional: Install security tools
git clone https://github.com/jimmy058910/jmo-security-repo.git
cd jmo-security-repo
make tools
make verify-env
```

**For contributing/development:** [CONTRIBUTING.md](CONTRIBUTING.md)

---

## First Scan

### Interactive Wizard (Recommended for Beginners)

```bash
jmotools wizard
```

The wizard guides you through:

- Profile selection (fast/balanced/deep)
- Target discovery (repos, images, URLs)
- Docker vs native mode
- Command preview before execution

**Non-interactive:** `jmotools wizard --yes`

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
| `fast` | 8 | 5-10 min | Pre-commit, PR validation |
| `balanced` | 21 | 18-25 min | CI/CD pipelines |
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
| `findings.json` | Machine-readable findings |
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
| Platform setup | [docs/PLATFORM_SPECIFIC.md](docs/PLATFORM_SPECIFIC.md) |

### Key Features

| Feature | Guide |
|---------|-------|
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
jmotools setup --check       # Verify installation
jmotools setup --auto-install # Auto-install (Linux/macOS/WSL)
```

### Permission denied

```bash
find scripts -type f -name "*.sh" -exec chmod +x {} +
```

### More help

- [docs/CI_TROUBLESHOOTING.md](docs/CI_TROUBLESHOOTING.md) - CI/CD issues
- [docs/PLATFORM_SPECIFIC.md](docs/PLATFORM_SPECIFIC.md) - Platform-specific issues
- [GitHub Issues](https://github.com/jimmy058910/jmo-security-repo/issues)

---

## Support

- **Ko-fi:** <https://ko-fi.com/jmogaming>
- **GitHub Sponsors:** <https://github.com/sponsors/jimmy058910>
- **Newsletter:** <https://jmotools.com/subscribe.html>
