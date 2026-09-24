# JMo Security - Command Reference

Quick command reference for common operations.

---

## Scanning Commands

```bash
# Scan a repository (every applicable scanner)
jmo scan --repo .

# Quick scan with a narrowed tool list
jmo scan --repo . --tools trufflehog semgrep trivy

# Skip specific tools
jmo scan --repo . --skip-tools zap nuclei

# Custom results directory
jmo scan --repo . --results-dir ~/audits/myapp

# Multi-target scanning
jmo scan --repo . --image nginx:latest --url https://example.com

# Allow missing tools
jmo scan --repo . --allow-missing-tools

# Exclude directories
jmo scan --repo . --exclude "tests/*" --exclude "vendor/*"
```

---

## Reporting Commands

```bash
# Generate all reports
jmo report results

# With profiling
jmo report results --profile

# With failure threshold
jmo report results --fail-on HIGH
```

---

## CI/CD Commands

```bash
# CI mode (scan + report + exit code)
jmo ci --repo . --fail-on CRITICAL

# Diff between scans
jmo diff results-baseline/ results-current/ --format md
```

---

## History & Trends

```bash
# View scan history
jmo history list

# Trend analysis
jmo trends analyze --days 30
```

---

## Docker Commands

```bash
# Full scan
docker run --rm -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results-dir /scan/results

# Quick scan with a narrowed tool list
docker run --rm -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results-dir /scan/results --tools trufflehog semgrep trivy

# With history persistence
docker run --rm \
  -v "$(pwd):/scan" \
  -v "$(pwd)/.jmo:/scan/.jmo" \
  ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results-dir /scan/results
```

---

## View Results

```bash
# View summary
cat results/summaries/SUMMARY.md

# Open dashboard
open results/summaries/dashboard.html           # macOS
xdg-open results/summaries/dashboard.html       # Linux
cmd.exe /c start results/summaries/dashboard.html  # WSL
```

---

## Key Output Files

| File | Purpose |
|------|---------|
| `SUMMARY.md` | Quick overview with severity counts |
| `dashboard.html` | Interactive HTML dashboard |
| `findings.json` | Machine-readable unified findings |
| `findings.sarif` | GitHub Code Scanning format |

---

## Tool Management

```bash
# Check tool status
jmo tools check

# Install missing tools (cross-platform)
jmo tools install

# Update outdated tools
jmo tools update

# Update only critical tools
jmo tools update --critical-only

# Show outdated tools
jmo tools outdated

# List available tools
jmo tools list

# Uninstall JMo and optionally tools
jmo tools uninstall
```

---

## Troubleshooting

```bash
# Check installed tools
jmo tools check

# Install missing tools
jmo tools install

# Increase timeout for large repos
jmo scan --repo . --timeout 1200

# Reduce parallelism
jmo scan --repo . --threads 2
```

---

## Configuration Files

| File | Purpose |
|------|---------|
| `jmo.yml` | Main configuration |
| `jmo.suppress.yml` | Suppression rules |

---

**Full Documentation:** [USER_GUIDE.md](USER_GUIDE.md) | [DOCKER_README.md](DOCKER_README.md) | [RESULTS_GUIDE.md](RESULTS_GUIDE.md)

**Last Updated:** February 2026
