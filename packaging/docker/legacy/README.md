# Legacy Dockerfiles

This directory contains deprecated Docker variants that are no longer actively maintained.

## Archived Files

- **Dockerfile.alpine** - Alpine Linux variant (v0.6.0-v0.9.0, deprecated v1.0.0)

## Current Docker Variants (v1.0.0+)

The project uses **4 actively maintained Docker variants**:

| Variant | Tag | Size | Tools | Best For |
|---------|-----|------|-------|----------|
| **Full** | `:latest` | ~1.97 GB | 28 | Complete audits, local dev |
| **Balanced** | `:balanced` | ~1.41 GB | 21 | Production CI/CD, regular audits |
| **Slim** | `:slim` | ~557 MB | 15 | Cloud-focused, IaC, containers |
| **Fast** | `:fast` | ~502 MB | 8 | CI/CD gates, pre-commit hooks |

See [docs/DOCKER_VARIANTS_MASTER.md](../../../docs/DOCKER_VARIANTS_MASTER.md) for complete tool distribution and usage guide.

## Alpine Deprecation (v1.0.0)

**Why Alpine was deprecated:**

1. **Limited tool support**: Alpine's musl libc caused compatibility issues with 8+ tools:
   - Semgrep, Bandit, Falco, AFL++ (glibc dependencies)
   - MobSF, Lynis, ScanCode, cdxgen (Python binary extensions)

2. **Maintenance burden**: Separate Alpine-specific fixes and workarounds (e.g., rustworkx arm64 timeouts)

3. **Better alternatives**:
   - Slim variant (557 MB) provides **15 tools** vs Alpine's 7 tools
   - Only 43 MB larger than Alpine (600 MB) but 2x tool coverage

4. **Version management**: Alpine not synced by `update_versions.py` (would diverge)

**Migration Path:**

```bash
# Old (Alpine, deprecated)
docker pull ghcr.io/jimmy058910/jmo-security:alpine

# New (Slim variant, recommended)
docker pull ghcr.io/jimmy058910/jmo-security:slim

# Or use Fast variant for minimal footprint (502 MB, 8 tools)
docker pull ghcr.io/jimmy058910/jmo-security:fast
```

**Tool Comparison:**

| Tool Category | Alpine (7 tools) | Slim (15 tools) | Fast (8 tools) |
|---------------|------------------|-----------------|----------------|
| Secrets | TruffleHog | TruffleHog | TruffleHog |
| SBOM | Syft | Syft | Syft |
| Vuln Scanning | Trivy, OSV-Scanner, Grype | Trivy, OSV-Scanner, Grype, Dependency-Check | Trivy, OSV-Scanner |
| Dockerfile | Hadolint | Hadolint | Hadolint |
| DAST | - | Nuclei | Nuclei |
| Cloud CSPM | - | Prowler, Kubescape | - |
| License | - | Bearer | - |
| Multi-language SAST | - | Horusec | - |

**Recommendation:** Use **Slim variant** for cloud/IaC/container security (Alpine's original use case) with 2x tool coverage.

## Version Management

All 4 active variants are synced via:

```bash
python3 scripts/dev/update_versions.py --update-all
python3 scripts/dev/update_versions.py --sync
```

**CI/CD:** `.github/workflows/release.yml` builds all 4 variants on version tags.

## See Also

- [Docker Variants Master](../../../docs/DOCKER_VARIANTS_MASTER.md) — Complete tool distribution
- [Docker Usage Guide](../../../docs/DOCKER_README.md) — Docker deep-dive
- [Version Management](../../../docs/VERSION_MANAGEMENT.md) — Tool version control
