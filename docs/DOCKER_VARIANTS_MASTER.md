# Docker Variants Master Reference

**Last Updated:** 2025-11-11

## Overview

JMo Security provides **4 optimized Docker image variants** for different use cases and resource constraints. Variants are differentiated by the number of security tools included and the target scan duration.

### Variant Summary Table

| Variant | Tag | Size | Tools | Docker-Ready | Scan Time | Best For |
|---------|-----|------|-------|--------------|-----------|----------|
| **Full** | `:latest`, `:0.9.0`, `:0.9` | ~1.97 GB | 28 | 26 | 40-70 min | Complete security audits, local development, deep scans |
| **Balanced** | `:balanced`, `:0.9.0-balanced` | ~1.41 GB | 21 | 21 | 18-25 min | Production CI/CD, regular audits, balanced coverage |
| **Slim** | `:slim`, `:0.9.0-slim` | ~557 MB | 15 | 15 | 12-18 min | Cloud-focused, IaC, container security |
| **Fast** | `:fast`, `:0.9.0-fast` | ~502 MB | 8 | 8 | 5-10 min | CI/CD gates, pre-commit hooks, quick validation |

**Notes:**

- **28 total tools**: 26 Docker-ready (automatically included), 2 manual install (MobSF, Akto)
- **Scan times**: Estimated for typical repository (10K-50K LOC, 100-500 dependencies)
- **Alpine deprecated**: Replaced by balanced/slim variants with better tool coverage

## Tool Distribution Across Variants

### Legend

- ✅ **Included** in this variant
- ❌ **Excluded** from this variant
- 🔧 **Manual install required** (MobSF, Akto)

### Secrets Detection (4 tools)

| Tool | Category | Full | Balanced | Slim | Fast | Notes |
|------|----------|------|----------|------|------|-------|
| **TruffleHog** | Secrets (Verified) | ✅ | ✅ | ✅ | ✅ | Core tool, always included |
| **Nosey Parker** | Secrets (Deep) | ✅ | ❌ | ❌ | ❌ | Deep profile only, regex-based |
| **Semgrep** | SAST (Multi-language) | ✅ | ❌ | ❌ | ❌ | Full SAST in Full variant |
| **Semgrep-Secrets** | Secrets (Semgrep rules) | ✅ | ❌ | ❌ | ❌ | Semgrep secret detection rules |

### Static Analysis (SAST) (3 tools)

| Tool | Category | Full | Balanced | Slim | Fast | Notes |
|------|----------|------|----------|------|------|-------|
| **Semgrep** | SAST (Multi-language) | ✅ | ❌ | ❌ | ❌ | 4000+ rules, 30+ languages |
| **Bandit** | SAST (Python) | ✅ | ❌ | ❌ | ❌ | Python-specific security checks |
| **Gosec** | SAST (Go) | ✅ | ✅ | ❌ | ❌ | Go security scanner |

### Software Composition Analysis (SCA) (5 tools)

| Tool | Category | Full | Balanced | Slim | Fast | Notes |
|------|----------|------|----------|------|------|-------|
| **Syft** | SBOM Generation | ✅ | ✅ | ✅ | ✅ | Core SBOM tool, always included |
| **Trivy** | Vuln + Misconfig | ✅ | ✅ | ✅ | ✅ | Core scanner, always included |
| **OSV-Scanner** | OSV Database | ✅ | ✅ | ✅ | ✅ | Google OSV, always included |
| **Grype** | Vulnerability Scanner | ✅ | ✅ | ✅ | ❌ | Anchore scanner |
| **Dependency-Check** | OWASP Dependency Check | ✅ | ❌ | ✅ | ❌ | OWASP vuln database |

### Infrastructure as Code (IaC) (2 tools)

| Tool | Category | Full | Balanced | Slim | Fast | Notes |
|------|----------|------|----------|------|------|-------|
| **Checkov** | IaC Policy | ✅ | ❌ | ❌ | ❌ | Terraform, CloudFormation, K8s |
| **Checkov-CICD** | CI/CD Pipeline Security | ✅ | ❌ | ❌ | ❌ | GitHub Actions, GitLab CI |

### Container Security (1 tool)

| Tool | Category | Full | Balanced | Slim | Fast | Notes |
|------|----------|------|----------|------|------|-------|
| **Hadolint** | Dockerfile Linting | ✅ | ✅ | ✅ | ✅ | Dockerfile best practices |

### Cloud Security (CSPM) (2 tools)

| Tool | Category | Full | Balanced | Slim | Fast | Notes |
|------|----------|------|----------|------|------|-------|
| **Prowler** | Cloud CSPM | ✅ | ✅ | ✅ | ❌ | AWS/Azure/GCP/K8s auditing |
| **Kubescape** | Kubernetes Security | ✅ | ✅ | ✅ | ❌ | K8s RBAC, NSA/CISA frameworks |

### Dynamic Application Security Testing (DAST) (3 tools)

| Tool | Category | Full | Balanced | Slim | Fast | Notes |
|------|----------|------|----------|------|------|-------|
| **OWASP ZAP** | DAST (Web) | ✅ | ✅ | ❌ | ❌ | Web app security testing |
| **Nuclei** | DAST (Templates) | ✅ | ✅ | ✅ | ✅ | 4000+ vulnerability templates |
| **Akto** | API Security | 🔧 | 🔧 | 🔧 | 🔧 | Manual install, business logic |

### Runtime Security (2 tools)

| Tool | Category | Full | Balanced | Slim | Fast | Notes |
|------|----------|------|----------|------|------|-------|
| **Falco** | Runtime Monitoring | ✅ | ❌ | ❌ | ❌ | eBPF-based, deep profile only |
| **Trivy-RBAC** | K8s RBAC Scanner | ✅ | ❌ | ❌ | ❌ | Kubernetes RBAC misconfig |

### Malware Detection (1 tool)

| Tool | Category | Full | Balanced | Slim | Fast | Notes |
|------|----------|------|----------|------|------|-------|
| **YARA** | Malware Patterns | ✅ | ❌ | ❌ | ❌ | Web shells, backdoors, cryptominers |

### System Hardening (1 tool)

| Tool | Category | Full | Balanced | Slim | Fast | Notes |
|------|----------|------|----------|------|------|-------|
| **Lynis** | System Auditing | ✅ | ❌ | ❌ | ❌ | Unix security, CIS baselines |

### Fuzzing (1 tool)

| Tool | Category | Full | Balanced | Slim | Fast | Notes |
|------|----------|------|----------|------|------|-------|
| **AFL++** | Coverage-Guided Fuzzing | ✅ | ❌ | ❌ | ❌ | Deep profile only, binaries |

### Mobile Security (1 tool)

| Tool | Category | Full | Balanced | Slim | Fast | Notes |
|------|----------|------|----------|------|------|-------|
| **MobSF** | Mobile Security | 🔧 | 🔧 | 🔧 | 🔧 | Manual install, Android/iOS |

### License Compliance (2 tools)

| Tool | Category | Full | Balanced | Slim | Fast | Notes |
|------|----------|------|----------|------|------|-------|
| **Bearer** | Security + Privacy | ✅ | ✅ | ✅ | ❌ | Data flow, OWASP risks |
| **ScanCode** | License Compliance | ✅ | ❌ | ❌ | ❌ | License detection, provenance |

### Code Quality (2 tools)

| Tool | Category | Full | Balanced | Slim | Fast | Notes |
|------|----------|------|----------|------|------|-------|
| **Horusec** | Multi-language SAST | ✅ | ✅ | ✅ | ❌ | 18 languages, 10+ analyzers |
| **cdxgen** | SBOM Generator | ✅ | ❌ | ❌ | ❌ | CycloneDX format |

### Utility Tools (2 tools)

| Tool | Category | Full | Balanced | Slim | Fast | Notes |
|------|----------|------|----------|------|------|-------|
| **shellcheck** | Shell Script Linting | ✅ | ❌ | ❌ | ❌ | Bash/sh script analysis |
| **shfmt** | Shell Formatter | ✅ | ❌ | ❌ | ❌ | Bash/sh formatting |

## Variant-Specific Details

### Full Variant (`:latest`)

**Size:** ~1.97 GB | **Tools:** 28 (26 Docker-ready + 2 manual)

**Use Cases:**

- Complete security audits (pre-release validation)
- Local development with comprehensive coverage
- Security research and vulnerability discovery
- Compliance scanning (SOC 2, PCI DSS, HIPAA)

**Included Tools (28):**

1. TruffleHog (secrets)
2. Nosey Parker (secrets, deep)
3. Semgrep (SAST)
4. Semgrep-Secrets (secrets)
5. Bandit (Python SAST)
6. Gosec (Go security)
7. Syft (SBOM)
8. Trivy (SCA + vuln)
9. OSV-Scanner (OSV DB)
10. Grype (vuln scanner)
11. Dependency-Check (OWASP)
12. Checkov (IaC)
13. Checkov-CICD (CI/CD)
14. Hadolint (Dockerfile)
15. Prowler (cloud CSPM)
16. Kubescape (K8s security)
17. OWASP ZAP (DAST)
18. Nuclei (DAST templates)
19. Akto (API security, manual)
20. Falco (runtime security)
21. Trivy-RBAC (K8s RBAC)
22. YARA (malware detection)
23. Lynis (system hardening)
24. AFL++ (fuzzing)
25. MobSF (mobile security, manual)
26. Bearer (license compliance)
27. ScanCode (license compliance)
28. Horusec (multi-language SAST)
29. cdxgen (SBOM)
30. shellcheck (shell linting)
31. shfmt (shell formatting)

**Excluded:** None (comprehensive coverage)

### Balanced Variant (`:balanced`)

**Size:** ~1.41 GB | **Tools:** 21 (all Docker-ready)

**Use Cases:**

- Production CI/CD pipelines (18-25 min scans)
- Regular security audits (weekly/monthly)
- Balanced coverage without specialized tools
- Resource-constrained environments

**Included Tools (21):**

1. TruffleHog (secrets)
2. Gosec (Go security)
3. Syft (SBOM)
4. Trivy (SCA + vuln)
5. OSV-Scanner (OSV DB)
6. Grype (vuln scanner)
7. Hadolint (Dockerfile)
8. Prowler (cloud CSPM)
9. Kubescape (K8s security)
10. OWASP ZAP (DAST)
11. Nuclei (DAST templates)
12. Bearer (license compliance)
13. Horusec (multi-language SAST)

**Excluded (7 specialized tools):**

- Nosey Parker (secrets, regex-based)
- Semgrep (SAST, slow on large codebases)
- Semgrep-Secrets (secrets)
- Bandit (Python-specific)
- Checkov (IaC, not needed for all projects)
- Checkov-CICD (CI/CD pipeline security)
- Falco (runtime security, eBPF kernel modules)
- Trivy-RBAC (K8s RBAC, niche use case)
- YARA (malware detection, specialized)
- Lynis (system hardening, not code scanning)
- AFL++ (fuzzing, requires compilation)
- ScanCode (license compliance, slow)
- cdxgen (SBOM, Syft preferred)
- shellcheck (shell linting, niche)
- shfmt (shell formatting, niche)

### Slim Variant (`:slim`)

**Size:** ~557 MB | **Tools:** 15 (all Docker-ready)

**Use Cases:**

- Cloud-focused security scanning (IaC, containers)
- CI/CD pipelines with faster pull times
- Kubernetes and cloud-native applications
- Resource-constrained environments (512 MB-1 GB RAM)

**Included Tools (15):**

1. TruffleHog (secrets)
2. Syft (SBOM)
3. Trivy (SCA + vuln + misconfig)
4. OSV-Scanner (OSV DB)
5. Grype (vuln scanner)
6. Dependency-Check (OWASP)
7. Hadolint (Dockerfile)
8. Prowler (cloud CSPM)
9. Kubescape (K8s security)
10. Nuclei (DAST templates, fast)
11. Bearer (license compliance)
12. Horusec (multi-language SAST)

**Excluded (13 tools):**

- All specialized tools from Balanced + Full
- OWASP ZAP (replaced by Nuclei for speed)
- Gosec (Go-specific, less common)

### Fast Variant (`:fast`)

**Size:** ~502 MB | **Tools:** 8 (all Docker-ready)

**Use Cases:**

- CI/CD gates (5-10 min scans)
- Pre-commit hooks (local developer validation)
- Pull request checks (quick feedback)
- Initial triage scans

**Included Tools (8):**

1. TruffleHog (secrets, verified)
2. Syft (SBOM generation)
3. Trivy (SCA + vuln + misconfig)
4. OSV-Scanner (OSV DB, fast)
5. Hadolint (Dockerfile linting)
6. Nuclei (DAST templates, fast)

**Excluded (20 tools):**

- All SAST tools (Semgrep, Bandit, Gosec, Horusec)
- IaC tools (Checkov, Checkov-CICD)
- Cloud CSPM (Prowler, Kubescape)
- DAST (OWASP ZAP)
- Runtime security (Falco, Trivy-RBAC)
- Specialized tools (YARA, Lynis, AFL++, MobSF, Akto)
- License compliance (Bearer, ScanCode, cdxgen)
- Utility tools (shellcheck, shfmt)

## Choosing the Right Variant

### Decision Tree

```text
START: What is your primary use case?

├─ Complete security audit (pre-release, compliance)
│  → Use FULL variant (:latest)
│     - 28 tools, 40-70 min scans
│     - Best for: Security teams, audits, compliance

├─ Production CI/CD (daily/weekly scans)
│  → Use BALANCED variant (:balanced)
│     - 21 tools, 18-25 min scans
│     - Best for: DevOps, regular audits, balanced coverage

├─ Cloud/K8s/IaC focused (containers, infrastructure)
│  → Use SLIM variant (:slim)
│     - 15 tools, 12-18 min scans
│     - Best for: Cloud-native, IaC, container security

└─ Fast feedback (pre-commit, PR checks)
   → Use FAST variant (:fast)
      - 8 tools, 5-10 min scans
      - Best for: Developers, CI gates, quick validation
```

### Resource Constraints

| Variant | Min RAM | Min Disk | Min CPU | Network Bandwidth |
|---------|---------|----------|---------|-------------------|
| **Full** | 2 GB | 4 GB | 2 cores | Medium (initial pull) |
| **Balanced** | 1.5 GB | 3 GB | 2 cores | Medium (initial pull) |
| **Slim** | 1 GB | 2 GB | 1 core | Low (fast pull) |
| **Fast** | 512 MB | 1.5 GB | 1 core | Low (fast pull) |

## Alpine Deprecation Notice

**Dockerfile.alpine has been deprecated** and replaced by the balanced/slim variants.

**Rationale:**

1. **Limited tool support**: Alpine's musl libc caused compatibility issues with 8+ tools (Semgrep, Bandit, Falco, AFL++, MobSF, Lynis, ScanCode, cdxgen)
2. **Maintenance burden**: Separate Alpine-specific fixes and workarounds
3. **Better alternatives**: Slim variant (557 MB) provides better tool coverage than Alpine (~600 MB)
4. **glibc dependency**: Many security tools require glibc (not available in Alpine)

**Migration Path:**

- Old: `docker pull ghcr.io/jimmy058910/jmo-security:alpine`
- New: `docker pull ghcr.io/jimmy058910/jmo-security:slim`

**If you still need Alpine:**

Alpine Dockerfiles are archived in `packaging/docker/legacy/` for reference, but are no longer maintained or tested.

## Version Management

All 4 Docker variants are **automatically synced** via the version management system:

```bash
# Update all variants at once
python3 scripts/dev/update_versions.py --update-all

# Sync Dockerfiles with versions.yaml
python3 scripts/dev/update_versions.py --sync

# Verify consistency
python3 scripts/dev/update_versions.py --sync --dry-run
```

**Key Files:**

- `versions.yaml` — Single source of truth for all tool versions
- `Dockerfile` — Full variant (28 tools)
- `Dockerfile.balanced` — Balanced variant (21 tools)
- `Dockerfile.slim` — Slim variant (15 tools)
- `Dockerfile.fast` — Fast variant (8 tools)

**CI/CD Automation:**

- `.github/workflows/release.yml` — Builds all 4 variants on version tags
- `.github/workflows/version-check.yml` — Weekly version consistency checks
- `.github/workflows/weekly-tool-update.yml` — Automated weekly tool updates

## See Also

- [Docker Usage Guide](DOCKER_README.md) — Complete Docker guide
- [Version Management](VERSION_MANAGEMENT.md) — Tool version control
- [Quick Start](../QUICKSTART.md) — 5-minute setup guide
- [User Guide](USER_GUIDE.md) — Comprehensive reference
