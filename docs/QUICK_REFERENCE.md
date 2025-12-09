# JMo Security - Quick Reference Guide

**Last Updated**: 2025-10-23

---

## 🚀 Common Commands

### Scanning

```bash
# Fast scan (5-8 min, 3 tools)
jmo scan --repo . --profile-name fast

# Balanced scan (15-20 min, 8 tools)
jmo scan --repo . --profile-name balanced

# Deep scan (30-60 min, 11 tools)
jmo scan --repo . --profile-name deep

# Custom results directory
jmo scan --repo ~/projects/myapp --results-dir ~/security-audits/myapp-2025-10-23

# Multi-target scanning
jmo scan --repo . --image nginx:latest --url https://example.com --results-dir results
```

### Reporting

```bash
# Generate all reports (JSON, MD, YAML, HTML, SARIF)
jmo report results

# With profiling (generates timings.json)
jmo report results --profile

# With failure threshold
jmo report results --fail-on HIGH  # Exit code 1 if HIGH+ found
```

### Automation via Make

```bash
make fast           # Fast scan + report
make balanced       # Balanced scan + report
make full           # Deep scan + report

make attack-navigator  # Open ATT&CK threat map (auto-serve)
```

---

## 📊 Understanding Results

**📖 For complete results triage guide, see:**

- **[RESULTS_GUIDE.md](RESULTS_GUIDE.md)** - Complete 12,000-word guide
- **[RESULTS_QUICK_REFERENCE.md](RESULTS_QUICK_REFERENCE.md)** - One-page printable triage card

### Quick View

```bash
# View summary
cat results/summaries/SUMMARY.md

# Open dashboard
xdg-open results/summaries/dashboard.html         # Linux
open results/summaries/dashboard.html             # macOS
cmd.exe /c start results/summaries/dashboard.html # WSL
```

### Key Output Files

| File | Purpose |
|------|---------|
| `SUMMARY.md` | Quick overview with severity counts |
| `dashboard.html` | Interactive HTML dashboard |
| `findings.json` | Machine-readable unified findings |
| `findings.sarif` | GitHub Code Scanning format |
| `COMPLIANCE_SUMMARY.md` | Multi-framework compliance report |

**See [RESULTS_QUICK_REFERENCE.md](RESULTS_QUICK_REFERENCE.md) for triage workflow and filtering commands.**

---

## 🐳 Docker Usage

### Quick Start

```bash
# Scan current directory
docker run --rm -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --profile-name balanced

# View results
docker run --rm -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:latest \
  report /scan/results
```

### Image Variants

| Variant | Size | Tools | Use Case |
|---------|------|-------|----------|
| `latest` (full) | ~2.5 GB | All 11 tools | Complete audits |
| `slim` | ~1.8 GB | 8 core tools | CI/CD pipelines |
| `alpine` | ~800 MB | 6 essential tools | Fast validation |

---

## 🔧 Troubleshooting

### Common Issues

#### "Tool not found" errors

```bash
# Check installed tools
make verify-env

# Install missing tools
make tools

# Allow missing tools (write empty stubs)
jmo scan --repo . --allow-missing-tools
```

#### Slow scans

```bash
# Use faster profile
jmo scan --repo . --profile-name fast

# Reduce parallelism (less CPU load)
jmo scan --repo . --threads 2

# Increase timeout for large repos
jmo scan --repo . --timeout 1200
```

#### High false positive rate

```bash
# Apply suppressions
vim jmo.suppress.yml

# Exclude test directories
jmo scan --repo . --exclude "tests/*" --exclude "vendor/*"

# Use balanced profile (fewer aggressive tools)
jmo scan --repo . --profile-name balanced
```

---

## 📁 File Locations

### Configuration

- `jmo.yml` - Main configuration (profiles, tools, thresholds)
- `jmo.suppress.yml` - Suppression rules (optional)
- `.bandit` - Bandit-specific config (optional)

### Results Structure

```text
results/
├── individual-repos/          # Per-repo tool outputs
│   └── <repo-name>/
│       ├── trufflehog.json
│       ├── semgrep.json
│       └── ...
├── individual-images/         # Container image scans
├── individual-iac/            # IaC file scans
├── individual-web/            # Web app scans
├── individual-gitlab/         # GitLab repo scans
├── individual-k8s/            # K8s cluster scans
└── summaries/                 # Unified reports
    ├── findings.json
    ├── SUMMARY.md
    ├── dashboard.html
    └── ...
```

---

## 🎓 Learn More

- **User Guide**: [USER_GUIDE.md](USER_GUIDE.md)
- **Quick Start**: [../QUICKSTART.md](../QUICKSTART.md)
- **Docker Guide**: [DOCKER_README.md](DOCKER_README.md)
- **Examples**: [examples/](examples/)
- **Project Homepage**: <https://jmotools.com>

---

## 💡 Pro Tips

### Speed Up Scans

1. Use `fast` profile for pre-commit checks
2. Exclude large directories: `--exclude "node_modules/*"`
3. Increase threads: `--threads 8` (for multi-core systems)
4. Cache results: Reuse `results/` directory between runs

### Reduce Noise

1. Apply suppressions for test fixtures and vendor code
2. Filter dashboard by path pattern (e.g., `src/*.py`)
3. Use `--fail-on HIGH` to focus on critical issues
4. Review `SUPPRESSIONS.md` to track what's suppressed

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    pip install jmo-security
    jmo ci --repo . --profile-name fast --fail-on CRITICAL

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results/summaries/findings.sarif
```

### ATT&CK Navigator

```bash
# Auto-serve with browser opening
make attack-navigator

# Manual upload
# 1. Open: https://mitre-attack.github.io/attack-navigator/
# 2. Click '+' → 'Open Existing Layer' → 'Upload from local'
# 3. Select: results/summaries/attack-navigator.json
```

---

## 🆘 Getting Help

- **Documentation**: [docs/](.)
- **Issues**: <https://github.com/jimmy058910/jmo-security-repo/issues>
- **Discussions**: <https://github.com/jimmy058910/jmo-security-repo/discussions>

---

**Last Reviewed**: 2025-10-23
