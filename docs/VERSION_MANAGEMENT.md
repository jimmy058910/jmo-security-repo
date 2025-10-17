# Version Management Guide

**Status:** ✅ Implemented (v0.6.1+)
**Related:** [ROADMAP.md #14](../ROADMAP.md#1-tool-version-consistency--automated-dependency-management), [Issue #46](https://github.com/jimmy058910/jmo-security-repo/issues/46), [Issue #12](https://github.com/jimmy058910/jmo-security-repo/issues/12)

## Table of Contents

- [Overview](#overview)
- [The 5-Layer System](#the-5-layer-system)
- [Quick Start](#quick-start)
- [Central Version Registry](#central-version-registry)
- [Automation Scripts](#automation-scripts)
- [CI/CD Integration](#cicd-integration)
- [Dependabot Configuration](#dependabot-configuration)
- [Monthly Update Workflow](#monthly-update-workflow)
- [Troubleshooting](#troubleshooting)

---

## Overview

JMo Security Suite uses a **5-layer version management system** to ensure Docker images and native installations always use the same tool versions. This prevents critical issues like the Trivy v0.58.1 → v0.67.2 discrepancy that caused 16 CVEs to be missed (see [ROADMAP.md #14](../ROADMAP.md#1-tool-version-consistency--automated-dependency-management)).

### Why This Matters

**Real-world impact:**
- **Before:** Docker Trivy v0.58.1 (9 weeks old) missed 1 CRITICAL + 7 HIGH CVEs
- **After:** Automated checks prevent version drift across 3 Dockerfiles + install scripts

### Key Components

1. **[versions.yaml](../versions.yaml)** — Single source of truth for all tool versions
2. **[update_versions.py](../scripts/dev/update_versions.py)** — Automation script for updates
3. **[version-check.yml](../.github/workflows/version-check.yml)** — Weekly CI checks + issue creation
4. **[dependabot.yml](../.github/dependabot.yml)** — Python/Docker/Actions dependency updates
5. **Dockerfile sync** — Automated version propagation across 3 Docker variants

---

## The 5-Layer System

### Layer 1: Central Version Registry

**[versions.yaml](../versions.yaml)** contains:

```yaml
python_tools:
  semgrep:
    version: "1.94.0"
    pypi_package: "semgrep"
    description: "Multi-language SAST scanner"
    critical: true

binary_tools:
  trivy:
    version: "0.67.2"
    github_repo: "aquasecurity/trivy"
    description: "Vulnerability/misconfig/secrets scanner"
    critical: true
```

**Fields:**
- `version`: Current pinned version (X.Y.Z format)
- `critical`: If `true`, updates required within 7 days
- `github_repo`: For binary releases (e.g., `owner/repo`)
- `pypi_package`: For Python packages
- `description`: Human-readable purpose
- `update_check`: Command to check for latest version

### Layer 2: Automated Version Checker

**[.github/workflows/version-check.yml](../.github/workflows/version-check.yml)**

Runs weekly (Sunday 00:00 UTC) to:
- ✅ Check for latest tool versions via GitHub/PyPI APIs
- ✅ Detect Trivy version mismatches across Dockerfiles (critical)
- ✅ Create GitHub issues for outdated CRITICAL tools (auto-labeled)
- ✅ Validate Dockerfile consistency (no hardcoded versions)

### Layer 3: Dockerfile Build-Time Variables

All Dockerfiles use parameterized versions:

```dockerfile
# ✅ CORRECT: Read from ARG/ENV
RUN TRIVY_VERSION="0.67.2" && \
    curl -sSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/..."

# ❌ WRONG: Hardcoded version
RUN curl -sSL "https://github.com/aquasecurity/trivy/releases/download/v0.67.2/..."
```

**Benefit:** Single command updates all 3 Dockerfiles (full, slim, alpine)

### Layer 4: Update Automation Script

**[scripts/dev/update_versions.py](../scripts/dev/update_versions.py)**

```bash
# Check for updates
python3 scripts/dev/update_versions.py --check-latest

# Update specific tool
python3 scripts/dev/update_versions.py --tool trivy --version 0.68.0

# Sync all Dockerfiles
python3 scripts/dev/update_versions.py --sync

# Generate report
python3 scripts/dev/update_versions.py --report
```

### Layer 5: Dependabot Configuration

**[.github/dependabot.yml](../.github/dependabot.yml)**

Tracks:
- ✅ Python packages (via `pip` ecosystem)
- ✅ Docker base images (`ubuntu:22.04`, `alpine:3.18`)
- ✅ GitHub Actions versions

**Does NOT track:**
- ❌ Binary tools (trivy, trufflehog, syft) — use `update_versions.py` instead
- ❌ Custom installations (ZAP, AFL++, Falco) — manual updates required

---

## Quick Start

### Check Current Versions

```bash
# View all tool versions
python3 scripts/dev/update_versions.py --report

# Check for available updates
python3 scripts/dev/update_versions.py --check-latest
```

### Update a Tool

```bash
# 1. Update versions.yaml
python3 scripts/dev/update_versions.py --tool trivy --version 0.68.0

# 2. Sync all Dockerfiles
python3 scripts/dev/update_versions.py --sync

# 3. Verify changes
git diff Dockerfile Dockerfile.slim Dockerfile.alpine

# 4. Test locally
make docker-build

# 5. Commit
git add versions.yaml Dockerfile*
git commit -m "deps(tools): update trivy to v0.68.0"
```

### Validate Consistency

```bash
# Dry-run check (CI uses this)
python3 scripts/dev/update_versions.py --sync --dry-run

# Exit code 0 = in sync, 1 = out of sync
echo $?
```

---

## Central Version Registry

### File Structure

**[versions.yaml](../versions.yaml)** has 4 main sections:

```yaml
schema_version: "1.0"

# Python packages installed via pip/pipx
python_tools:
  bandit: { version: "1.7.10", pypi_package: "bandit", critical: false }
  semgrep: { version: "1.94.0", pypi_package: "semgrep", critical: true }
  checkov: { version: "3.2.255", pypi_package: "checkov", critical: true }
  ruff: { version: "0.14.0", pypi_package: "ruff", critical: false }

# Binary releases from GitHub
binary_tools:
  trufflehog:
    version: "3.84.2"
    github_repo: "trufflesecurity/trufflehog"
    release_pattern: "trufflehog_{version}_linux_{arch}.tar.gz"
    architectures: { amd64: "amd64", arm64: "arm64" }
    critical: true

  trivy:
    version: "0.67.2"
    github_repo: "aquasecurity/trivy"
    release_pattern: "trivy_{version}_Linux-{arch}.tar.gz"
    architectures: { amd64: "64bit", arm64: "ARM64" }
    critical: true
    notes: "CRITICAL: Outdated versions miss CVEs (ROADMAP #14)"

  syft: { version: "1.18.1", github_repo: "anchore/syft", critical: true }
  hadolint: { version: "2.12.0", github_repo: "hadolint/hadolint", critical: false }
  noseyparker: { version: "0.24.0", github_repo: "praetorian-inc/noseyparker", critical: false }
  shfmt: { version: "3.8.0", github_repo: "mvdan/sh", critical: false }
  falcoctl: { version: "0.11.0", github_repo: "falcosecurity/falcoctl", critical: false }

# Special installation tools
special_tools:
  zap:
    version: "2.15.0"
    github_repo: "zaproxy/zaproxy"
    release_pattern: "ZAP_{version}_Linux.tar.gz"
    critical: true
    installation: "tar.gz with Java dependency"

  aflplusplus:
    version: "4.21c"
    github_repo: "AFLplusplus/AFLplusplus"
    critical: false
    installation: "Source build required"

# Docker base images
docker_images:
  ubuntu: { version: "22.04", registry: "docker.io", image: "ubuntu" }
  alpine: { version: "3.18", registry: "docker.io", image: "alpine" }

# Update policies
update_policies:
  critical_tools: [trivy, trufflehog, semgrep, checkov, zap, syft]
  description: "Critical tools must be updated within 7 days of new release"
  automated_check_schedule: "Weekly (Sunday 00:00 UTC)"
  manual_review_schedule: "First Monday of each month"

# Audit trail
version_history:
  - date: "2025-01-16"
    action: "Initial version registry created"
    updated_by: "automation"
    notes: "Fixed Trivy 0.58.1 → 0.67.2 inconsistency"
```

### Critical vs. Non-Critical Tools

**Critical tools** (update within 7 days):
- Security scanners: trivy, trufflehog, semgrep, checkov, syft, zap
- Impact: Outdated versions miss vulnerabilities/secrets

**Non-critical tools** (update monthly):
- Linters: bandit, ruff, hadolint, shfmt
- Optional: noseyparker, falcoctl, aflplusplus
- Impact: Lower risk if outdated

---

## Automation Scripts

### update_versions.py Usage

```bash
# === Checking for Updates ===

# Check all tools for updates
python3 scripts/dev/update_versions.py --check-latest

# Check outdated + create GitHub issues (CI uses this)
python3 scripts/dev/update_versions.py --check-outdated --create-issues

# === Updating Tools ===

# Update a single tool
python3 scripts/dev/update_versions.py --tool trivy --version 0.68.0
# Output: Updated trivy: 0.67.2 → 0.68.0

# Update multiple tools (run sequentially)
python3 scripts/dev/update_versions.py --tool semgrep --version 1.95.0
python3 scripts/dev/update_versions.py --tool checkov --version 3.2.260

# === Syncing Dockerfiles ===

# Apply versions.yaml to all Dockerfiles
python3 scripts/dev/update_versions.py --sync
# Output: Updated Dockerfile, Dockerfile.slim, Dockerfile.alpine

# Dry-run check (CI validation)
python3 scripts/dev/update_versions.py --sync --dry-run
# Exit 0 = in sync, 1 = out of sync

# === Reporting ===

# Generate version report
python3 scripts/dev/update_versions.py --report
```

**Output Example:**

```
================================================================================
JMo Security Suite - Version Consistency Report
================================================================================

Python Tools:
--------------------------------------------------------------------------------
  bandit          v1.7.10       ⚪ Normal
                → Python security linter
  semgrep         v1.94.0       🔴 CRITICAL
                → Multi-language SAST scanner
  checkov         v3.2.255      🔴 CRITICAL
                → IaC security scanner
  ruff            v0.14.0       ⚪ Normal
                → Python linter and formatter

Binary Tools:
--------------------------------------------------------------------------------
  trufflehog      v3.84.2       🔴 CRITICAL
                → Verified secrets scanner (primary)
  syft            v1.18.1       🔴 CRITICAL
                → SBOM generator
  trivy           v0.67.2       🔴 CRITICAL
                → Vulnerability/misconfig/secrets scanner
  hadolint        v2.12.0       ⚪ Normal
                → Dockerfile linter
```

### Exit Codes

- `0` — Success
- `1` — Validation errors or version mismatch detected
- `2` — Missing dependencies (PyYAML, gh CLI)

---

## CI/CD Integration

### Weekly Version Check Workflow

**[.github/workflows/version-check.yml](../.github/workflows/version-check.yml)**

**Trigger:** Weekly (Sunday 00:00 UTC) + manual dispatch

**Jobs:**

1. **check-versions**
   - Checks latest versions via GitHub/PyPI APIs
   - Generates version report
   - Creates GitHub issues for outdated CRITICAL tools
   - Validates Dockerfile sync with versions.yaml

2. **check-dockerfile-consistency**
   - Scans for hardcoded versions in Dockerfiles
   - Checks Trivy version across all 3 Dockerfiles (critical)
   - Fails on mismatch

3. **check-python-deps**
   - Checks PyPI for security tool updates (bandit, semgrep, checkov, ruff)
   - Creates notices for available updates

### Manual Trigger

```bash
# Trigger from GitHub UI: Actions → Version Consistency Check → Run workflow

# Or via GitHub CLI:
gh workflow run version-check.yml -f create_issues=true
```

### CI Validation

All PRs automatically validate:

```bash
# In .github/workflows/ci.yml (quick-checks job)
python3 scripts/dev/update_versions.py --sync --dry-run || exit 1
```

---

## Dependabot Configuration

**[.github/dependabot.yml](../.github/dependabot.yml)** handles:

### Python Dependencies

```yaml
- package-ecosystem: "pip"
  directory: "/"
  schedule:
    interval: "weekly"
    day: "monday"
  groups:
    development-dependencies:
      patterns: ["pytest*", "black*", "ruff*"]
      update-types: ["minor", "patch"]
```

**Tracks:** requirements-dev.txt (pytest, coverage, black, etc.)
**Does NOT track:** Security tools in Dockerfiles (use update_versions.py)

### Docker Base Images

```yaml
- package-ecosystem: "docker"
  directory: "/"
  schedule:
    interval: "weekly"
    day: "monday"
```

**Tracks:** `ubuntu:22.04`, `alpine:3.18` in FROM statements
**Does NOT track:** Binary tools installed in RUN layers

### GitHub Actions

```yaml
- package-ecosystem: "github-actions"
  directory: "/"
  schedule:
    interval: "weekly"
    day: "monday"
  groups:
    github-actions:
      patterns: ["*"]
      update-types: ["patch"]
```

**Tracks:** `actions/checkout@v4`, `actions/setup-python@v5`, etc.

### Review Process

1. Dependabot creates PR weekly (Monday 09:00 UTC)
2. Auto-labels: `dependencies`, `python|docker|ci`
3. Auto-requests review from `jimmy058910`
4. Groups minor/patch updates to reduce noise

---

## Monthly Update Workflow

**Recommended process** (first Monday of each month):

### Step 1: Check for Updates

```bash
# Get latest versions
python3 scripts/dev/update_versions.py --check-latest

# Example output:
# [warn] trivy: 0.67.2 → 0.68.0 (UPDATE AVAILABLE)
# [warn] semgrep: 1.94.0 → 1.95.1 (UPDATE AVAILABLE)
# [ok] trufflehog: 3.84.2 (latest)
```

### Step 2: Review Release Notes

For each outdated CRITICAL tool:

```bash
# Trivy
gh release view v0.68.0 --repo aquasecurity/trivy

# Semgrep
gh release view v1.95.1 --repo semgrep/semgrep

# Checkov
pip show checkov  # Check changelog URL
```

**Prioritize:**
- 🔴 Security fixes (CVE patches, false positive reductions)
- 🟡 New detection rules (SAST/secrets/IaC)
- ⚪ Features (new scan types, performance)

### Step 3: Update and Test

```bash
# Update critical tools first
python3 scripts/dev/update_versions.py --tool trivy --version 0.68.0
python3 scripts/dev/update_versions.py --tool semgrep --version 1.95.1

# Sync Dockerfiles
python3 scripts/dev/update_versions.py --sync

# Build and test locally
make docker-build

# Run smoke tests
docker run --rm ghcr.io/jimmy058910/jmo-security:latest --help
docker run --rm ghcr.io/jimmy058910/jmo-security:latest scan --help

# Test actual scanning
docker run --rm -v $(pwd):/scan \
  ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results /scan/results --profile fast
```

### Step 4: Commit and Release

```bash
# Commit version updates
git add versions.yaml Dockerfile*
git commit -m "deps(tools): update trivy v0.68.0, semgrep v1.95.1

- trivy: 0.67.2 → 0.68.0 (CVE database updates)
- semgrep: 1.94.0 → 1.95.1 (new SAST rules)

Related: ROADMAP #14, Issue #46"

# Push and create PR
git push origin feature/update-tools-jan-2025
gh pr create --title "deps(tools): monthly tool updates (Jan 2025)"
```

### Step 5: Monitor CI

Wait for:
- ✅ version-check.yml validates consistency
- ✅ ci.yml tests pass (Ubuntu/macOS × Python 3.10/3.11/3.12)
- ✅ Docker builds succeed (multi-arch: amd64, arm64)

---

## Troubleshooting

### "Dockerfiles are out of sync with versions.yaml"

**Cause:** Manual edits to Dockerfiles without updating versions.yaml

**Fix:**

```bash
# Check what's out of sync
python3 scripts/dev/update_versions.py --sync --dry-run

# Apply versions.yaml to Dockerfiles
python3 scripts/dev/update_versions.py --sync
```

### "CRITICAL: Trivy version mismatch detected"

**Cause:** Inconsistent Trivy versions across Dockerfile variants

**Fix:**

```bash
# Check current state
grep "TRIVY_VERSION" Dockerfile Dockerfile.slim Dockerfile.alpine

# Update versions.yaml
python3 scripts/dev/update_versions.py --tool trivy --version 0.68.0

# Sync all Dockerfiles
python3 scripts/dev/update_versions.py --sync

# Verify
grep "TRIVY_VERSION" Dockerfile Dockerfile.slim Dockerfile.alpine
```

### "Failed to check latest version"

**Cause:** GitHub rate limiting or missing `gh` CLI

**Fix:**

```bash
# Install GitHub CLI
brew install gh  # macOS
sudo apt install gh  # Ubuntu

# Authenticate
gh auth login

# Retry
python3 scripts/dev/update_versions.py --check-latest
```

### Dependabot PR Conflicts

**Cause:** Dependabot updated Python package, but versions.yaml outdated

**Fix:**

```bash
# Merge Dependabot PR first
gh pr merge <PR-number> --squash

# Update versions.yaml to match
python3 scripts/dev/update_versions.py --tool semgrep --version 1.95.0

# Sync Dockerfiles
python3 scripts/dev/update_versions.py --sync
```

---

## Related Documentation

- [ROADMAP.md #14](../ROADMAP.md#1-tool-version-consistency--automated-dependency-management) — Full 5-layer system design
- [Issue #46](https://github.com/jimmy058910/jmo-security-repo/issues/46) — Tool version consistency tracking
- [Issue #12](https://github.com/jimmy058910/jmo-security-repo/issues/12) — Dependency locking & updates
- [CLAUDE.md](../CLAUDE.md) — AI assistant development guidance

---

## Quick Reference

```bash
# === Daily Operations ===
python3 scripts/dev/update_versions.py --report          # View current versions
python3 scripts/dev/update_versions.py --check-latest    # Check for updates

# === Update Workflow ===
python3 scripts/dev/update_versions.py --tool <name> --version <X.Y.Z>
python3 scripts/dev/update_versions.py --sync
git add versions.yaml Dockerfile*
git commit -m "deps(tools): update <name> to vX.Y.Z"

# === CI Validation ===
python3 scripts/dev/update_versions.py --sync --dry-run  # Check consistency

# === Advanced ===
python3 scripts/dev/update_versions.py --check-outdated --create-issues  # Auto-issue
```

---

**Last updated:** 2025-01-16
**Maintainer:** jimmy058910
**Status:** Production-ready
