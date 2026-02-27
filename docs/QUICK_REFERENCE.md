# JMo Security - Command Reference

Quick command reference for common operations.

---

## Scanning Commands

```bash
# Fast scan (8 tools, 5-10 min)
jmo scan --repo . --profile-name fast

# Slim scan (14 tools, 12-18 min)
jmo scan --repo . --profile-name slim

# Balanced scan (18 tools, 18-25 min)
jmo scan --repo . --profile-name balanced

# Deep scan (28 tools, 40-70 min)
jmo scan --repo . --profile-name deep

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
jmo ci --repo . --profile-name fast --fail-on CRITICAL

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
# Balanced scan
docker run --rm -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:balanced \
  scan --repo /scan --results-dir /scan/results

# Fast scan
docker run --rm -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:fast \
  scan --repo /scan --results-dir /scan/results

# With history persistence
docker run --rm \
  -v "$(pwd):/scan" \
  -v "$(pwd)/.jmo:/scan/.jmo" \
  ghcr.io/jimmy058910/jmo-security:balanced \
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
# Check tool status for your profile
jmo tools check --profile balanced

# Install missing tools (cross-platform)
jmo tools install --profile balanced

# Update outdated tools
jmo tools update

# Update only critical tools
jmo tools update --critical-only

# Show outdated tools
jmo tools outdated

# List tools by profile
jmo tools list --profile deep

# Uninstall JMo and optionally tools
jmo tools uninstall
```

---

## Troubleshooting

```bash
# Check installed tools
jmo tools check --profile balanced

# Install missing tools
jmo tools install --profile balanced

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
