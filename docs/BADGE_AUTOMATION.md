# Badge Automation Guide

## Overview

JMo Security uses **auto-updating badges** that pull from live PyPI data. No manual edits are ever needed to README badges.

## How It Works

### Dynamic Badge URLs

All badges use dynamic endpoints that query PyPI in real-time:

```markdown
<!-- ✅ CORRECT: Auto-updating from PyPI -->
[![PyPI version](https://badge.fury.io/py/jmo-security.svg)](https://badge.fury.io/py/jmo-security)
[![Python Versions](https://img.shields.io/pypi/pyversions/jmo-security.svg)](https://pypi.org/project/jmo-security/)

<!-- ❌ WRONG: Hardcoded version (will become stale) -->
[![PyPI version](https://img.shields.io/badge/pypi-v0.7.1-blue.svg)](https://pypi.org)
```

### Badge CDN Caching

Badge services cache images for performance:

- **Shields.io:** 5-15 minute cache
- **Badge.fury.io:** 10-30 minute cache
- **PyPI CDN:** 1-5 minute cache

**Expected Timeline:**

1. **T+0 min:** Release workflow publishes to PyPI
2. **T+1 min:** PyPI API returns new version
3. **T+5 min:** Shields.io cache expires, fetches new version
4. **T+15 min:** Badge.fury.io cache expires, fetches new version
5. **T+30 min:** All CDN nodes worldwide show new version

## Verification Workflow

### Automated CI Verification

Every release triggers badge verification:

```yaml
# .github/workflows/release.yml
verify-badges:
  runs-on: ubuntu-latest
  needs: pypi-publish
  steps:
    - name: Wait for PyPI to propagate (60s)
      run: sleep 60
    - name: Verify badges match pyproject.toml
      run: bash scripts/dev/verify_badges.sh
```

**Purpose:** Catch version mismatches early, ensure badges auto-update correctly.

### Manual Verification

```bash
# Check badge versions vs local version
make verify-badges

# Force badge cache refresh (makes 5 requests to different CDN nodes)
bash scripts/dev/verify_badges.sh --fix

# Example output:
# 📦 Local version (pyproject.toml): 0.7.1
# 🐍 PyPI version: 0.7.1
# 🏷️  Badge version (shields.io): 0.7.1
# ✅ PyPI matches local version
# ✅ Badge matches PyPI version
```

## Troubleshooting

### Issue: Badge Shows Old Version (0.6.0 instead of 0.7.1)

**Cause:** CDN caching (normal behavior)

**Solution:**

```bash
# 1. Verify PyPI has the new version
curl -s https://pypi.org/pypi/jmo-security/json | jq -r '.info.version'
# Should output: 0.7.1

# 2. Force badge cache refresh
make verify-badges

# 3. Wait 15-30 minutes for global CDN propagation
# Check badge URL directly:
curl -sL https://img.shields.io/pypi/v/jmo-security.svg
```

**Timeline:**

- ✅ **Immediate:** PyPI API returns 0.7.1
- ⏳ **5-15 min:** Shields.io cache refreshes
- ⏳ **15-30 min:** All CDN nodes updated globally

### Issue: Badge Verification Fails in CI

**Symptom:**

```text
❌ Version mismatch:
   Badge:  0.6.0
   PyPI:   0.7.1
```

**Causes & Solutions:**

| Cause | Solution | Time to Fix |
|-------|----------|-------------|
| **CDN caching** | Wait 15 minutes, re-run workflow | 15-30 min |
| **PyPI propagation delay** | Wait 5 minutes, re-run workflow | 5-10 min |
| **Version mismatch** | Fix `pyproject.toml`, re-release | Immediate |

**Re-run Workflow:**

```bash
# Trigger manual re-run after waiting
gh run rerun <run-id>

# Or manually verify
make verify-badges
```

### Issue: Badge Shows Wrong Color/Status

**Shields.io badge parameters:**

```markdown
<!-- Default (auto-color based on version) -->
https://img.shields.io/pypi/v/jmo-security.svg

<!-- Custom color -->
https://img.shields.io/pypi/v/jmo-security.svg?color=blue

<!-- Add label -->
https://img.shields.io/pypi/v/jmo-security.svg?label=version
```

**Current badges in README.md:**

```bash
# Find all badge URLs
grep "badge.fury.io\|shields.io/pypi" README.md
```

## Release Checklist

### Pre-Release

- [x] Update version in `pyproject.toml`
- [x] Update `CHANGELOG.md` with user-facing changes
- [x] Commit: `git commit -m "release: vX.Y.Z"`
- [x] Tag: `git tag vX.Y.Z && git push --tags`

### During Release (Automated)

- [x] PyPI publish via Trusted Publishers (OIDC)
- [x] Docker images built (full/slim/alpine)
- [x] GitHub release created
- [x] Badge verification (60s after PyPI publish)

### Post-Release (Manual Verification - Optional)

```bash
# 1. Wait 5 minutes for PyPI propagation
sleep 300

# 2. Verify badges
make verify-badges

# 3. Check PyPI page renders correctly
open https://pypi.org/project/jmo-security/

# 4. Verify badge images (force refresh in browser)
# Ctrl+Shift+R (hard refresh) on README in GitHub

# 5. Check Docker Hub README (if enabled)
open https://hub.docker.com/r/jmogaming/jmo-security
```

## Badge Types Used

### Version Badges

| Badge | Service | Cache | Purpose |
|-------|---------|-------|---------|
| ![PyPI version](https://badge.fury.io/py/jmo-security.svg) | badge.fury.io | 10-30 min | Primary version badge |
| ![Python Versions](https://img.shields.io/pypi/pyversions/jmo-security.svg) | shields.io | 5-15 min | Python version support |

### Status Badges

- **CI Status:** `![Tests](https://github.com/.../workflows/ci.yml/badge.svg)`
- **Coverage:** `![codecov](https://codecov.io/.../badge.svg)`
- **Docker Pulls:** `![Docker Pulls](https://img.shields.io/docker/pulls/...)`
- **License:** `![License](https://img.shields.io/badge/License-MIT-yellow.svg)` (static)

## Best Practices

### ✅ DO

- Use dynamic badge URLs (shields.io, badge.fury.io)
- Let badges auto-update from PyPI
- Verify after releases with `make verify-badges`
- Wait 15-30 minutes for CDN propagation

### ❌ DON'T

- Hardcode version numbers in badge URLs
- Manually edit README.md to update badge versions
- Panic if badges lag 15-30 minutes after release
- Use static badge images

## Advanced: Custom Badge Endpoints

### Shields.io Endpoint Builder

Visit [shields.io](https://shields.io) to generate custom badges:

**Example: Custom label + color**

```markdown
[![Custom](https://img.shields.io/pypi/v/jmo-security.svg?label=stable&color=success)](https://pypi.org/project/jmo-security/)
```

**Available styles:**

- `?style=flat` (default)
- `?style=flat-square`
- `?style=for-the-badge`
- `?style=plastic`

### Badge.fury.io Options

**Version badge (current):**

```markdown
[![PyPI version](https://badge.fury.io/py/jmo-security.svg)](https://badge.fury.io/py/jmo-security)
```

**Download count (optional):**

```markdown
[![Downloads](https://pepy.tech/badge/jmo-security)](https://pepy.tech/project/jmo-security)
```

## Monitoring Badge Health

### Weekly Badge Check (Manual)

```bash
# Add to weekly maintenance checklist
echo "=== Weekly Badge Health Check ===" >> maintenance.log
make verify-badges >> maintenance.log
echo "" >> maintenance.log
```

### CI Integration

Badge verification runs automatically:

- **On every release:** `.github/workflows/release.yml` (line 341)
- **On every PR/push:** `.github/workflows/ci.yml` (line 60)

**CI job output:**

```text
🏷️  Verifying PyPI badge versions...
📦 Local version (pyproject.toml): 0.7.1
🐍 PyPI version: 0.7.1
🏷️  Badge version (shields.io): 0.7.1
✅ PyPI matches local version
✅ Badge matches PyPI version
```

## References

- **Shields.io Documentation:** <https://shields.io>
- **Badge.fury.io:** <https://badge.fury.io>
- **PyPI JSON API:** <https://warehouse.pypa.io/api-reference/json.html>
- **GitHub Badges Guide:** <https://docs.github.com/en/actions/managing-workflow-runs/adding-a-workflow-status-badge>

---

**Last Updated:** 2025-10-25 (v0.7.1)
**Maintainer:** James Moceri
