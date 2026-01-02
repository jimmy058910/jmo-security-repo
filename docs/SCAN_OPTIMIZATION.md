# Scan Speed Optimization Guide

Comprehensive guide for optimizing JMo Security scan performance without sacrificing security coverage.

## Overview

A typical balanced profile scan (18 tools) takes 18-25 minutes. This guide covers strategies to reduce scan times by 30-60% while maintaining thorough security coverage.

**Key Metrics:**

| Profile | Tools | Default Time | Optimized Time | Reduction |
|---------|-------|--------------|----------------|-----------|
| fast | 8 | 5-10 min | 3-6 min | ~40% |
| slim | 14 | 12-18 min | 8-12 min | ~35% |
| balanced | 18 | 18-25 min | 12-18 min | ~30% |
| deep | 28 | 40-70 min | 30-50 min | ~25% |

## Quick Wins (Immediate Impact)

### 1. Increase Thread Count

The default thread count is conservative. Modern CPUs can handle more parallelism.

**Current defaults in `jmo.yml`:**

```yaml
profiles:
  fast:
    threads: 8      # Already optimized
  slim:
    threads: 4      # Can increase
  balanced:
    threads: 4      # Can increase
  deep:
    threads: 2      # Conservative for stability
```

**Recommended settings based on CPU cores:**

| CPU Cores | fast | slim | balanced | deep |
|-----------|------|------|----------|------|
| 4 cores | 4 | 3 | 3 | 2 |
| 8 cores | 8 | 6 | 6 | 4 |
| 16 cores | 12 | 10 | 8 | 6 |
| 32+ cores | 16 | 12 | 10 | 8 |

**How to apply:**

```yaml
# In jmo.yml, update your preferred profile:
profiles:
  balanced:
    threads: 6  # Increase from 4 to 6 for 8-core CPU
```

Or use the `--threads` CLI flag:

```bash
jmo scan --repo . --profile balanced --threads 6
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

### 3. Use Appropriate Profile for Task

Don't use `deep` profile for quick checks. Match profile to use case:

| Use Case | Recommended Profile | Time |
|----------|-------------------|------|
| Pre-commit hook | `fast` | 3-6 min |
| PR validation | `fast` or `slim` | 5-12 min |
| Nightly CI/CD | `balanced` | 15-20 min |
| Release audit | `deep` | 40-60 min |
| Compliance audit | `deep` | 40-60 min |

```bash
# Quick pre-commit check
jmo scan --repo . --profile fast

# Full production scan
jmo scan --repo . --profile balanced
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

Not all tools are relevant for all targets. Create custom profiles:

**In `jmo.yml`:**

```yaml
profiles:
  # For Python projects only
  python-fast:
    tools:
      - trufflehog
      - semgrep
      - bandit      # Python-specific
      - trivy
      - checkov
    threads: 6
    timeout: 300
    per_tool:
      semgrep:
        flags:
          - --config
          - p/python

  # For container images only
  container-scan:
    tools:
      - trivy
      - grype
      - syft
      - hadolint
    threads: 4
    timeout: 300

  # For IaC/cloud only
  iac-scan:
    tools:
      - checkov
      - trivy
      - kubescape
      - prowler
    threads: 4
    timeout: 400
```

**Usage:**

```bash
jmo scan --repo ./python-app --profile python-fast
jmo scan --image nginx:latest --profile container-scan
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
      jmo scan --repo . --profile fast
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
time jmo scan --repo . --profile balanced 2>&1 | tee scan.log

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

### 14. Profile-Specific Timeouts

Set aggressive timeouts for fast scans, generous for deep scans:

```yaml
profiles:
  fast:
    timeout: 300    # 5 minutes max per tool
  balanced:
    timeout: 600    # 10 minutes max per tool
  deep:
    timeout: 900    # 15 minutes max per tool
    retries: 1      # Retry once on timeout
```

## Docker Optimizations

### 15. Use Pre-built Images

JMo Docker images have pre-cached databases:

```bash
# Use profile-specific images (databases pre-loaded)
docker run -v $PWD:/scan jmo-security:balanced scan --repo /scan
```

### 16. Mount Cache Volumes

Persist caches between Docker runs:

```bash
docker run \
  -v $PWD:/scan \
  -v jmo-trivy-cache:/root/.cache/trivy \
  -v jmo-grype-cache:/root/.cache/grype \
  -v jmo-nuclei-templates:/root/.nuclei-templates \
  jmo-security:balanced scan --repo /scan
```

## Optimization Checklist

Before running a scan, verify these settings:

- [ ] Using appropriate profile for the task
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
   jmo scan --repo . --profile balanced 2>&1 | grep -E "Running|Complete"
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
3. **Use appropriate profile** (fast for PRs, balanced for CI)
4. **Configure tool exclusions** (node_modules, .git, vendor)
5. **Set severity filters** for nuclei and trivy

**Expected improvements:**

- Fast profile: 5-10 min to 3-6 min (40% faster)
- Balanced profile: 18-25 min to 12-18 min (30% faster)
- Deep profile: 40-70 min to 30-50 min (25% faster)

## See Also

- [PROFILES_AND_TOOLS.md](PROFILES_AND_TOOLS.md) - Profile definitions and tool lists
- [USER_GUIDE.md](USER_GUIDE.md) - Complete configuration reference
- [DOCKER_README.md](DOCKER_README.md) - Docker-specific optimizations
