# Scan Speed Optimization Guide

Comprehensive guide for optimizing JMo Security scan performance without sacrificing security coverage.

## Overview

`jmo scan` considers every scanner in the tool matrix, and the target's content decides which ones run (see [TOOLS.md](TOOLS.md#when-each-tool-runs)). On a large repository that can take tens of minutes. This guide covers strategies to reduce scan times by 30-60% while maintaining thorough security coverage.

## Quick Wins (Immediate Impact)

### 1. Increase Thread Count

The default thread count is conservative. Modern CPUs can handle more parallelism.

**Current default in `jmo.yml`:**

```yaml
threads: 4      # Top-level default; can increase
```

**Recommended settings based on CPU cores:**

| CPU Cores | threads |
|-----------|---------|
| 4 cores | 3 |
| 8 cores | 6 |
| 16 cores | 8 |
| 32+ cores | 10 |

**How to apply:**

```yaml
# In jmo.yml:
threads: 6  # Increase from 4 to 6 for 8-core CPU
```

Or use the `--threads` CLI flag:

```bash
jmo scan --repo . --threads 6
```

Or set environment variable:

```bash
export JMO_THREADS=6
jmo scan --repo .
```

### 2. Pre-warm Vulnerability Database Caches

Several tools download vulnerability databases on first run. Pre-caching eliminates this delay.

**Tools with databases:**

| Tool | Cache Location | Size | Update Command |
|------|---------------|------|----------------|
| trivy | `~/.cache/trivy/` | ~900 MB | `trivy image --download-db-only` |
| grype | `~/.cache/grype/` | ~3.8 GB | `grype db update` |
| nuclei | `~/.nuclei-templates/` | ~200 MB | `nuclei -update-templates` |

**Pre-warm script:**

```bash
#!/bin/bash
# scripts/pre-warm-caches.sh

echo "Pre-warming security tool caches..."

# Trivy vulnerability database
echo "[1/3] Updating Trivy database..."
trivy image --download-db-only 2>/dev/null

# Grype vulnerability database
echo "[2/3] Updating Grype database..."
grype db update 2>/dev/null

# Nuclei templates
echo "[3/3] Updating Nuclei templates..."
nuclei -update-templates -silent 2>/dev/null

echo "Cache pre-warming complete!"
```

**Run before scans:**

```bash
# One-time setup or weekly refresh
./scripts/pre-warm-caches.sh

# Then run your scan
jmo scan --repo .
```

### 3. Narrow the Tool List for Quick Checks

A quick check does not need every scanner. Narrow the list with `--tools` (or `--skip-tools`) and keep the full matrix for nightly and release scans:

| Use Case | Tools |
|----------|-------|
| Pre-commit hook | `--tools trufflehog semgrep` |
| PR validation | `--tools trufflehog semgrep trivy` |
| Nightly CI/CD | all (no `--tools`) |
| Release or compliance audit | all (no `--tools`) |

```bash
# Quick pre-commit check
jmo scan --repo . --tools trufflehog semgrep

# Full production scan
jmo scan --repo .
```

## Tool-Specific Optimizations

### 4. Semgrep Optimizations

Semgrep can be slow on large codebases. Optimize with exclusions and rule selection.

**In `jmo.yml`:**

```yaml
per_tool:
  semgrep:
    timeout: 300
    flags:
      # Exclude large/generated directories
      - --exclude
      - node_modules
      - --exclude
      - .git
      - --exclude
      - vendor
      - --exclude
      - dist
      - --exclude
      - build
      - --exclude
      - "*.min.js"
      # Use specific rulesets instead of all
      - --config
      - p/security-audit
      - --config
      - p/secrets
      # Skip slow rules
      - --exclude-rule
      - generic.secrets.gitleaks.*
```

**For incremental scans (git repos only):**

```bash
# Only scan changed files (requires git)
semgrep scan --config auto --baseline-commit HEAD~1 .
```

### 5. Trivy Optimizations

Trivy scans for vulnerabilities, secrets, and misconfigurations. Focus on what you need.

**In `jmo.yml`:**

```yaml
per_tool:
  trivy:
    timeout: 300
    flags:
      - --no-progress
      # Scan only what you need (pick relevant scanners)
      - --scanners
      - vuln,secret,misconfig
      # Skip unfixed vulnerabilities (optional)
      # - --ignore-unfixed
      # Set severity threshold
      - --severity
      - CRITICAL,HIGH,MEDIUM
      # Skip dev dependencies (for package scanning)
      # - --skip-dev-dependencies
```

**For faster container scans:**

```yaml
per_tool:
  trivy:
    flags:
      - --no-progress
      - --scanners
      - vuln  # Skip misconfig for images
      - --severity
      - CRITICAL,HIGH
```

### 6. Nuclei Optimizations

Nuclei has 7000+ templates. Running all is slow. Focus on severity and category.

**In `jmo.yml`:**

```yaml
per_tool:
  nuclei:
    timeout: 300
    flags:
      # Limit by severity (critical+high is usually sufficient)
      - -severity
      - critical,high
      # Or limit by template count
      - -rl
      - "150"  # Rate limit: 150 requests/second
      - -c
      - "25"   # Concurrency: 25 parallel templates
      # Exclude slow/noisy templates
      - -exclude-tags
      - dos,fuzz
```

**For web scanning only:**

```yaml
per_tool:
  nuclei:
    flags:
      - -severity
      - critical,high,medium
      - -tags
      - cve,exposure,misconfiguration
```

### 7. Checkov Optimizations

Checkov scans IaC files. Skip irrelevant frameworks.

**In `jmo.yml`:**

```yaml
per_tool:
  checkov:
    timeout: 300
    flags:
      - --quiet
      - --compact
      # Only scan frameworks you use
      - --framework
      - terraform,kubernetes,dockerfile
      # Skip specific checks if too noisy
      # - --skip-check
      # - CKV_DOCKER_2,CKV_DOCKER_3
```

### 8. ZAP Optimizations

ZAP (DAST) can be very slow. Limit spider depth and scan duration.

**In `jmo.yml`:**

```yaml
per_tool:
  zap:
    timeout: 600
    flags:
      - -config
      - api.disablekey=true
      # Limit spider duration (minutes)
      - -config
      - spider.maxDuration=5
      # Limit spider depth
      - -config
      - spider.maxDepth=3
      # Disable slow passive scanners
      - -config
      - pscans.enableAllPassiveScanners=false
```

## Advanced Optimizations

### 9. Parallel Target Scanning

When scanning multiple repositories, JMo scans them in parallel.

```bash
# Scan multiple repos efficiently
jmo scan --repos-dir ./projects --threads 8

# Or use a targets file
jmo scan --targets repos.txt --threads 8
```

**Example `repos.txt`:**

```text
/path/to/repo1
/path/to/repo2
/path/to/repo3
```

### 10. Skip Tools Based on Target Type

Not all tools are relevant for all targets, and JMo already skips the ones that are not: hadolint runs only when Dockerfiles are present, shellcheck only with shell scripts, gosec only with Go sources, and zap and nuclei only on `--url` targets. To narrow further, name the tools:

```bash
# Python project: secrets, SAST, dependencies, IaC
jmo scan --repo ./python-app --tools trufflehog semgrep trivy checkov

# Container image only
jmo scan --image nginx:latest --tools trivy syft

# IaC only
jmo scan --repo ./infra --tools checkov trivy
```

To make a narrower list the default for a project, set a top-level `tools:` list in its `jmo.yml`:

```yaml
tools:
  - trufflehog
  - semgrep
  - trivy
  - checkov
threads: 6
timeout: 300
per_tool:
  semgrep:
    flags:
      - --config
      - p/python
```

### 11. Incremental/Differential Scanning

For CI/CD, only scan changed files:

```bash
# Get changed files from git
CHANGED_FILES=$(git diff --name-only HEAD~1)

# Create a temporary directory with only changed files
# (Tool-specific - semgrep supports this natively)
semgrep scan --baseline-commit HEAD~1 .
```

**CI/CD example (GitHub Actions):**

```yaml
- name: Get changed files
  id: changed-files
  uses: tj-actions/changed-files@v40

- name: Run security scan on changed files
  if: steps.changed-files.outputs.any_changed == 'true'
  run: |
    # Only scan if security-relevant files changed
    if echo "${{ steps.changed-files.outputs.all_changed_files }}" | grep -qE '\.(py|js|ts|go|java|yaml|yml|tf|json)$'; then
      jmo scan --repo . --tools trufflehog semgrep trivy
    fi
```

### 12. Cache Management

Large caches can slow down scans. Manage them periodically:

**Check cache sizes:**

```bash
du -sh ~/.cache/trivy/
du -sh ~/.cache/grype/
du -sh ~/.nuclei-templates/
```

**Clean old caches:**

```bash
# Remove old Trivy cache (keeps latest)
trivy clean --all

# Grype - remove and re-download
rm -rf ~/.cache/grype/
grype db update

# Nuclei - update templates
nuclei -update-templates
```

**Recommended schedule:**

| Cache | Refresh Frequency | Command |
|-------|------------------|---------|
| Trivy DB | Weekly | `trivy image --download-db-only` |
| Grype DB | Weekly | `grype db update` |
| Nuclei templates | Weekly | `nuclei -update-templates` |

## Performance Monitoring

### 13. Measure Scan Performance

Track which tools are slowest:

```bash
# Enable timing output
time jmo scan --repo . 2>&1 | tee scan.log

# Parse timing from results
grep -E "duration|elapsed" results/summaries/*.json
```

**Add custom timing wrapper:**

```bash
#!/bin/bash
# scripts/timed-scan.sh

start_time=$(date +%s)

jmo scan "$@"

end_time=$(date +%s)
duration=$((end_time - start_time))

echo ""
echo "=== Scan Performance ==="
echo "Total duration: ${duration}s ($(($duration / 60))m $(($duration % 60))s)"
```

### 14. Timeouts and Retries

Set one default timeout at the top level of `jmo.yml`, and give the slow tools more room in `per_tool`:

```yaml
timeout: 600      # 10 minutes max per tool
retries: 1        # Retry once on timeout
per_tool:
  semgrep:
    timeout: 900  # 15 minutes for a large codebase
```

For a one-off quick run, `--timeout` overrides the default:

```bash
jmo scan --repo . --tools trufflehog semgrep --timeout 300
```

## Docker Optimizations

### 15. Use Pre-built Images

The JMo Docker image has pre-cached databases:

```bash
# One image carries every scanner (databases pre-loaded)
docker run -v $PWD:/scan ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan
```

### 16. Mount Cache Volumes

Persist caches between Docker runs:

```bash
docker run \
  -v $PWD:/scan \
  -v jmo-trivy-cache:/root/.cache/trivy \
  -v jmo-grype-cache:/root/.cache/grype \
  -v jmo-nuclei-templates:/root/.nuclei-templates \
  ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan
```

## Optimization Checklist

Before running a scan, verify these settings:

- [ ] Tool list narrowed with `--tools` for quick checks
- [ ] Thread count matches available CPU cores
- [ ] Vulnerability databases are pre-cached
- [ ] Tool exclusions are configured (node_modules, .git, vendor)
- [ ] Timeouts are set appropriately
- [ ] Unnecessary tools are excluded for target type

## Troubleshooting Slow Scans

### Identify Bottlenecks

1. **Check which tool is slow:**

   ```bash
   # Watch scan progress
   jmo scan --repo . 2>&1 | grep -E "Running|Complete"
   ```

2. **Check resource usage:**

   ```bash
   # Monitor during scan
   htop  # or top
   ```

3. **Check network latency:**

   ```bash
   # Test connectivity to vulnerability databases
   curl -I https://ghcr.io/v2/
   curl -I https://nvd.nist.gov/
   ```

### Common Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| Trivy stuck downloading | Slow network | Pre-cache with `trivy image --download-db-only` |
| Semgrep timeout | Large codebase | Add more exclusions, increase timeout |
| Nuclei slow | Too many templates | Limit severity: `-severity critical,high` |
| High memory usage | Too many threads | Reduce thread count |
| ZAP timeout | Deep spidering | Limit spider: `spider.maxDuration=5` |

## Summary

**Top 5 optimizations for immediate impact:**

1. **Increase threads** to match CPU cores (biggest impact)
2. **Pre-cache vulnerability databases** before scans
3. **Narrow the tool list** with `--tools` for PRs and pre-commit; run everything nightly
4. **Configure tool exclusions** (node_modules, .git, vendor)
5. **Set severity filters** for nuclei and trivy

## See Also

- [TOOLS.md](TOOLS.md) - The tool matrix and when each tool runs
- [USER_GUIDE.md](USER_GUIDE.md) - Complete configuration reference
- [DOCKER_README.md](DOCKER_README.md) - Docker-specific optimizations
