# Docker v0.5.1 Push Instructions

**Date:** 2025-10-16
**Version:** v0.5.1 (Compliance Framework Integration)
**Image:** ghcr.io/jimmy058910/jmo-security:v0.5.1-full

---

## Build Status ✅

The Docker image `jmo-security:v0.5.1-full` has been **successfully built** with:

- ✅ All 11 security tools installed and verified
- ✅ Compliance framework integration (v0.5.1)
- ✅ Deep profile tested and working (10/10 tools ran)
- ✅ All compliance reports generated correctly

**Image Details:**

```text
IMAGE ID: bb6e674c2cf0
SIZE: 3.42GB
CREATED: 2025-10-16 06:20:00
TOOLS: trufflehog, noseyparker, semgrep, bandit, syft, trivy, checkov, hadolint, zap, falcoctl, afl++
```

---

## Tested Tools (10/10 ran successfully)

| # | Tool | Status | Notes |
|---|------|--------|-------|
| 1 | trufflehog | ✅ | Verified secrets scanner |
| 2 | noseyparker | ✅ | Comprehensive secrets (retry worked!) |
| 3 | semgrep | ✅ | Multi-language SAST |
| 4 | bandit | ✅ | Python-specific SAST |
| 5 | syft | ✅ | SBOM generator |
| 6 | trivy | ✅ | Vulnerability scanner |
| 7 | checkov | ✅ | IaC policy-as-code |
| 8 | hadolint | ✅ | Dockerfile linter |
| 9 | zap | ✅ | OWASP ZAP (web security) |
| 10 | afl++ | ✅ | Coverage-guided fuzzing |
| 11 | falcoctl | ✅ Installed | K8s runtime security (CLI tool for rule validation) |

**Note:** falcoctl is installed but not invoked by default scans (used for K8s rule management).

---

## Push Commands

### Prerequisites

You must have a GitHub Personal Access Token (PAT) with `write:packages` scope.

### Login to GitHub Container Registry

**Important:** The `gh auth token` does NOT have `write:packages` scope by default, which causes this error:

```text
error from registry: permission_denied: The token provided does not match expected scopes.
```

**Solution: Create a new PAT with correct scopes:**

1. Go to <https://github.com/settings/tokens/new>
2. Select scopes:
   - ✅ `write:packages` (required)
   - ✅ `read:packages` (required)
3. Generate token and copy it
4. Login:

```bash
echo "YOUR_NEW_PAT_HERE" | docker login ghcr.io -u jimmy058910 --password-stdin
```

### Push Images

```bash
# Push v0.5.1-full tag
docker push ghcr.io/jimmy058910/jmo-security:v0.5.1-full

# Push latest-full tag
docker push ghcr.io/jimmy058910/jmo-security:latest-full
```

**Expected Output:**

```text
The push refers to repository [ghcr.io/jimmy058910/jmo-security]
...
v0.5.1-full: digest: sha256:... size: 17234
```

---

## Verification After Push

### Test Pull and Scan

```bash
# Pull the new image
docker pull ghcr.io/jimmy058910/jmo-security:v0.5.1-full

# Verify tools
docker run --rm ghcr.io/jimmy058910/jmo-security:v0.5.1-full --help

# Run deep scan test
docker run --rm \
  -v $(pwd)/test-repo:/repo:ro \
  -v $(pwd)/results:/results \
  ghcr.io/jimmy058910/jmo-security:v0.5.1-full \
  ci --repo /repo --profile-name deep --results-dir /results --human-logs

# Verify compliance reports
ls results/summaries/ | grep -E "(COMPLIANCE|PCI|attack)"
```

**Expected:**

```text
COMPLIANCE_SUMMARY.md
PCI_DSS_COMPLIANCE.md
attack-navigator.json
```

---

## Release Checklist

After pushing to registry:

- [ ] Update [README.md](../README.md) with v0.5.1 image tags
- [ ] Update [QUICKSTART.md](../QUICKSTART.md) Docker examples
- [ ] Update [docs/DOCKER_README.md](DOCKER_README.md) with new version
- [ ] Update [.github/workflows/release.yml](../.github/workflows/release.yml) if needed
- [ ] Create GitHub release notes for v0.5.1
- [ ] Update [CHANGELOG.md](../CHANGELOG.md) (already done)
- [ ] Announce in project channels

---

## GitHub Actions Alternative

If manual push fails, use GitHub Actions release workflow:

1. Commit Dockerfile changes
2. Push to main branch
3. Create and push tag:
   ```bash
   git tag v0.5.1
   git push origin v0.5.1
   ```
4. Release workflow will automatically build and push Docker images

---

## Troubleshooting

### Authentication Failed

**Error:** `unauthenticated: User cannot be authenticated with the token provided`

**Solution:**
```bash
# Re-generate token with correct scopes
gh auth refresh -s write:packages

# Re-login
gh auth token | docker login ghcr.io -u jimmy058910 --password-stdin
```

### Permission Denied

**Error:** `permission_denied: The token provided does not match expected scopes`

**Solution:** PAT needs `write:packages` scope. Create new PAT:

1. Go to GitHub Settings → Developer settings → Personal access tokens
2. Generate new token (classic)
3. Select scope: `write:packages`
4. Copy token and use for login

### Image Too Large

**Warning:** Image is 3.42GB (includes AFL++ compiled binaries, ZAP with Java)

**Solution:** This is expected for full image. For smaller size, use:

- `jmo-security:v0.5.1-slim` (coming soon, without ZAP/AFL++)
- `jmo-security:v0.5.1-alpine` (coming soon, Alpine-based)

---

*Last Updated: 2025-10-16*
*Maintainer: James Moceri <general@jmogaming.com>*
