# Scan Profiles and Tools Reference

> **Canonical source for JMo Security scan profiles and tool definitions.**

This document is the authoritative reference for which tools are included in each scan profile. All profile definitions across the codebase (jmo.yml, tool_registry.py, wizard.py, Docker variants) MUST match this document.

## Table of Contents

- [Quick Reference](#quick-reference)
- [Profile Overview](#profile-overview)
- [Profile Tool Lists](#profile-tool-lists)
- [Tool Categories](#tool-categories)
- [Complete Tool Reference](#complete-tool-reference)
- [Manual Installation Tools](#manual-installation-tools)
- [Dependencies](#dependencies)
- [Installation Methods](#installation-methods)
- [Consistency Matrix](#consistency-matrix)

---

## Quick Reference

| Profile | Tools | Time | Use Case | Docker Tag |
|---------|-------|------|----------|------------|
| **fast** | 8 | 5-10 min | Pre-commit, PR validation | `jmo-security:fast` |
| **slim** | 14 | 12-18 min | Cloud/IaC (AWS/Azure/GCP/K8s) | `jmo-security:slim` |
| **balanced** | 18 | 18-25 min | Production scans, CI/CD | `jmo-security:balanced` |
| **deep** | 28 | 40-70 min | Compliance audits, pentests | `jmo-security:deep` |

**Installation:**

```bash
# Docker (all tools pre-installed)
docker run -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:balanced scan

# Native (install tools for profile)
pip install jmo-security
jmo tools install --profile balanced
```

---

## Profile Overview

### Fast Profile (8 tools)

**Purpose:** Quick validation for pre-commit hooks, pull requests, and CI gates.

**Best for:** Developers running local checks before pushing code.

**Tools included:** Core secrets detection, SAST, SCA, IaC scanning, and shell analysis.

### Slim Profile (14 tools)

**Purpose:** Cloud and infrastructure-focused scanning.

**Best for:** AWS/Azure/GCP environments, Kubernetes deployments, IaC repositories.

**Tools included:** Fast profile + cloud security (Prowler, Kubescape), additional SCA (Grype), data privacy (Bearer), and multi-language SAST (Horusec).

### Balanced Profile (18 tools)

**Purpose:** Production-ready CI/CD scanning with comprehensive coverage.

**Best for:** Regular security audits, CI/CD pipelines, release gates.

**Tools included:** Slim profile + DAST (ZAP), license scanning (ScanCode), SBOM generation (CDXgen), and Go-specific analysis (Gosec).

### Deep Profile (28 tools)

**Purpose:** Comprehensive security audits for compliance and penetration testing.

**Best for:** Pre-release validation, compliance audits (SOC2, PCI-DSS, HIPAA), security assessments.

**Tools included:** Balanced profile + backup secrets scanning (Nosey Parker), Python SAST (Bandit), malware detection (YARA), runtime security (Falco), fuzzing (AFL++), mobile security (MobSF), API security (Akto), and system hardening (Lynis).

---

## Profile Tool Lists

### Fast Profile (8 tools)

```yaml
fast:
  - trufflehog      # Verified secrets detection
  - semgrep         # Multi-language SAST
  - syft            # SBOM generation
  - trivy           # Vulnerabilities, secrets, misconfig
  - checkov         # IaC security
  - hadolint        # Dockerfile linting
  - nuclei          # Fast vulnerability scanner
  - shellcheck      # Shell script analysis
```

### Slim Profile (14 tools)

```yaml
slim:
  # Fast profile (8)
  - trufflehog
  - semgrep
  - syft
  - trivy
  - checkov
  - hadolint
  - nuclei
  - shellcheck
  # Additional (6)
  - prowler         # Multi-cloud CSPM (AWS/Azure/GCP/K8s)
  - kubescape       # Kubernetes security (NSA/CISA)
  - grype           # Vulnerability scanner (Anchore DB)
  - bearer          # Data privacy/SAST (GDPR/CCPA)
  - horusec         # Multi-language SAST (18+ languages)
  - dependency-check # OWASP SCA (NVD integration)
```

### Balanced Profile (18 tools)

```yaml
balanced:
  # Slim profile (14)
  - trufflehog
  - semgrep
  - syft
  - trivy
  - checkov
  - hadolint
  - nuclei
  - shellcheck
  - prowler
  - kubescape
  - grype
  - bearer
  - horusec
  - dependency-check
  # Additional (4)
  - zap             # OWASP ZAP - DAST
  - scancode        # License/copyright scanning
  - cdxgen          # CycloneDX SBOM (30+ languages)
  - gosec           # Go security analyzer
```

### Deep Profile (28 tools)

```yaml
deep:
  # Core scanning (14)
  - trufflehog
  - semgrep
  - syft
  - trivy
  - checkov
  - hadolint
  - nuclei
  - prowler
  - kubescape
  - grype
  - bearer
  - horusec
  - dependency-check
  - zap
  # Extended scanning (6)
  - scancode
  - cdxgen
  - gosec
  - yara            # Malware pattern detection
  - noseyparker     # Deep secrets scanning
  - bandit          # Python security linter
  # Tool variants (4)
  - semgrep-secrets # Semgrep with secrets rules
  - trivy-rbac      # Trivy RBAC scanning
  - checkov-cicd    # Checkov CI/CD config scanning
  - falco           # Runtime security
  # Specialized (4) - 3 require manual installation
  - akto            # API security (OWASP API Top 10) [MANUAL]
  - afl++           # Coverage-guided fuzzing [MANUAL]
  - mobsf           # Mobile security (Android/iOS) [MANUAL]
  - lynis           # System hardening audit
```

---

## Tool Categories

### Secrets Detection

| Tool | Profile | Description |
|------|---------|-------------|
| TruffleHog | fast+ | Verified secrets with 800+ detectors |
| Nosey Parker | deep | Deep regex-based secrets scanning |
| Semgrep-Secrets | deep | Semgrep with secrets-focused rules |

### SAST (Static Application Security Testing)

| Tool | Profile | Languages |
|------|---------|-----------|
| Semgrep | fast+ | 30+ languages |
| Bandit | deep | Python |
| Gosec | balanced+ | Go |
| Horusec | slim+ | 18+ languages |
| Bearer | slim+ | 12+ languages (privacy focus) |

### SCA (Software Composition Analysis)

| Tool | Profile | Description |
|------|---------|-------------|
| Trivy | fast+ | CVE/NVD database |
| Grype | slim+ | Anchore vulnerability DB |
| Dependency-Check | slim+ | OWASP NVD integration |
| OSV-Scanner | - | Google OSV database (not in profiles) |

### SBOM Generation

| Tool | Profile | Formats |
|------|---------|---------|
| Syft | fast+ | CycloneDX, SPDX, Syft JSON |
| CDXgen | balanced+ | CycloneDX (30+ languages) |

### IaC Security

| Tool | Profile | Targets |
|------|---------|---------|
| Checkov | fast+ | Terraform, CloudFormation, K8s, Dockerfile |
| Checkov-CICD | deep | GitHub Actions, GitLab CI, Jenkins |
| Hadolint | fast+ | Dockerfile best practices |
| Kubescape | slim+ | Kubernetes (NSA/CISA hardening) |
| Prowler | slim+ | AWS, Azure, GCP, Kubernetes |

### DAST (Dynamic Application Security Testing)

| Tool | Profile | Targets |
|------|---------|---------|
| Nuclei | fast+ | APIs, web apps (4000+ templates) |
| ZAP | balanced+ | Web applications (OWASP standard) |
| Akto | deep | API security (OWASP API Top 10) [MANUAL] |

### License & Compliance

| Tool | Profile | Description |
|------|---------|-------------|
| ScanCode | balanced+ | License detection, copyright scanning |

### Specialized Security

| Tool | Profile | Description |
|------|---------|-------------|
| YARA | deep | Malware pattern detection |
| Falco | deep | Runtime security rules |
| AFL++ | deep | Coverage-guided fuzzing [MANUAL] |
| MobSF | deep | Mobile app security [MANUAL] |
| Lynis | deep | System hardening audit |
| ShellCheck | fast+ | Shell script security |

---

## Complete Tool Reference

### All 28 Tools (Alphabetical)

| # | Tool | Version | Profiles | Installation | Critical |
|---|------|---------|----------|--------------|----------|
| 1 | AFL++ | 4.34c | deep | Manual | No |
| 2 | Akto | 1.53.7 | deep | Manual | No |
| 3 | Bandit | 1.9.2 | deep | pip | No |
| 4 | Bearer | 1.51.1 | slim+ | binary | No |
| 5 | CDXgen | 12.0.0 | balanced+ | npm | No |
| 6 | Checkov | 3.2.495 | fast+ | pip | Yes |
| 7 | Checkov-CICD | (variant) | deep | pip | No |
| 8 | Dependency-Check | 12.1.0 | slim+ | Java JAR | No |
| 9 | Falco | 0.11.4 | deep | binary | No |
| 10 | Gosec | 2.22.10 | balanced+ | binary | No |
| 11 | Grype | 0.104.0 | slim+ | binary | No |
| 12 | Hadolint | 2.14.0 | fast+ | binary | No |
| 13 | Horusec | 2.8.0 | slim+ | binary | No |
| 14 | Kubescape | 3.0.47 | slim+ | binary | Yes |
| 15 | Lynis | 3.1.3 | deep | apt/script | No |
| 16 | MobSF | 4.4.2 | deep | Manual | No |
| 17 | Nosey Parker | 0.24.0 | deep | binary | No |
| 18 | Nuclei | 3.5.1 | fast+ | binary | No |
| 19 | Prowler | 5.13.1 | slim+ | pip | Yes |
| 20 | ScanCode | 32.4.1 | balanced+ | pip | No |
| 21 | Semgrep | 1.144.0 | fast+ | pip | Yes |
| 22 | Semgrep-Secrets | (variant) | deep | pip | No |
| 23 | ShellCheck | 0.10.0 | fast+ | apt/binary | No |
| 24 | Syft | 1.38.0 | fast+ | binary | Yes |
| 25 | Trivy | 0.67.2 | fast+ | binary | Yes |
| 26 | Trivy-RBAC | (variant) | deep | binary | No |
| 27 | TruffleHog | 3.91.1 | fast+ | binary | Yes |
| 28 | YARA | 4.5.5 | deep | pip | No |
| 29 | ZAP | 2.16.1 | balanced+ | Java/binary | Yes |

**Notes:**

- "fast+" means included in fast and all larger profiles
- "(variant)" means same binary as parent tool, different configuration
- Versions from `versions.yaml` as of December 2025

### Critical Tools

These tools MUST be updated within 7 days of new releases:

- **trivy** - Outdated versions miss CVEs
- **trufflehog** - Outdated versions miss new secret patterns
- **semgrep** - Rule updates fix false negatives
- **checkov** - Policy updates for new cloud services
- **zap** - Security patches for scanner itself
- **syft** - SBOM accuracy depends on current version
- **prowler** - Cloud compliance rules update frequently
- **kubescape** - K8s hardening standards evolve

---

## Manual Installation Tools

Three tools require manual installation due to complex dependencies:

### AFL++ (Fuzzing)

**Why manual:** Requires LLVM/GCC development headers for compilation.

**Docker alternative:** Use `aflplusplus/aflplusplus` image.

```bash
# Ubuntu/Debian
sudo apt-get install -y build-essential clang llvm-14-dev
git clone https://github.com/AFLplusplus/AFLplusplus.git
cd AFLplusplus && make distrib && sudo make install
```

### MobSF (Mobile Security)

**Why manual:** Requires Android SDK components and significant storage (~2GB).

**Docker alternative:** Planned for v1.0.1.

```bash
pip install mobsf==4.4.2
# + Android SDK setup (see docs/MANUAL_INSTALLATION.md)
```

### Akto (API Security)

**Why manual:** Runs as separate Docker service with its own database.

```bash
git clone https://github.com/akto-api-security/akto.git
cd akto && docker-compose up -d
# Configure API key in ~/.jmo/akto.yml
```

---

## Dependencies

### Core Requirements

| Dependency | Version | Required For |
|------------|---------|--------------|
| **Python** | 3.10+ | JMo Security core |
| **pip** | latest | Python package installation |
| **Git** | 2.x+ | Repository scanning |

### Optional Requirements

| Dependency | Version | Required For |
|------------|---------|--------------|
| **Node.js** | 18+ (20 LTS recommended) | CDXgen SBOM generation |
| **Java** | 17+ (OpenJDK) | Dependency-Check, ZAP |
| **Docker** | 20.10+ | Docker mode, Akto |
| **Go** | 1.21+ | Building from source (optional) |

### Python Package Dependencies

```text
PyYAML >= 6.0          # Config file loading
croniter >= 1.0        # Schedule management
requests >= 2.31.0     # EPSS/KEV integration
rapidfuzz >= 3.0.0     # Cross-tool deduplication
rich >= 13.0           # Console formatting
```

### System Packages (Linux/Docker)

```bash
# Build dependencies (for pip packages with C extensions)
apt-get install -y build-essential gcc g++ libffi-dev libssl-dev

# For scancode-toolkit
apt-get install -y pkg-config libicu-dev

# Runtime
apt-get install -y git curl jq shellcheck ca-certificates
```

---

## Installation Methods

### Docker (Recommended for CI/CD)

**Zero installation required** - all tools pre-installed.

```bash
# Available tags match profiles
docker run -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:fast scan
docker run -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:slim scan
docker run -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:balanced scan
docker run -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:deep scan  # 25 tools, 3 manual
```

**Registries:**

- GitHub: `ghcr.io/jimmy058910/jmo-security`
- ECR: `public.ecr.aws/m2d8u2k1/jmo-security`
- Docker Hub: `jmogaming/jmo-security`

### Native/pip Installation

```bash
# Install JMo Security
pip install jmo-security

# Install tools for your profile
jmo tools install --profile balanced

# Verify installation
jmo tools check --profile balanced
```

### Homebrew (macOS/Linux)

```bash
brew install jmo-security
jmo tools install --profile balanced
```

### Winget (Windows)

```powershell
winget install jmo-security
jmo tools install --profile balanced
```

### Tool Installation Priority by Platform

| Platform | Methods (in order) |
|----------|-------------------|
| **Linux** | apt, pip, npm, binary download |
| **macOS** | brew, pip, npm, binary download |
| **Windows** | pip, npm, binary download, scoop |

---

## Consistency Matrix

All sources MUST match. This table tracks current status:

| Source | Fast | Slim | Balanced | Deep | Status |
|--------|------|------|----------|------|--------|
| **jmo.yml** | 8 | 14 | 18 | 28 | Canonical |
| **tool_registry.py** | 8 | 14 | 18 | 28 | Must match |
| **wizard.py** | 8 | 14 | 18 | 28 | Must match |
| **Dockerfile.fast** | 8 | - | - | - | Must match |
| **Dockerfile.slim** | - | 14 | - | - | Must match |
| **Dockerfile.balanced** | - | - | 18 | - | Must match |
| **Dockerfile (deep)** | - | - | - | 25* | *3 manual tools |

### Sync Check Commands

```bash
# Verify profile tool counts
python -c "
import yaml
with open('jmo.yml') as f:
    config = yaml.safe_load(f)
for profile in ['fast', 'slim', 'balanced', 'deep']:
    tools = config['profiles'][profile]['tools']
    print(f'{profile}: {len(tools)} tools')
"

# Expected output:
# fast: 8 tools
# slim: 14 tools
# balanced: 18 tools
# deep: 28 tools
```

---

## Updating This Document

When adding or removing tools:

1. Update `jmo.yml` (canonical source)
2. Update `scripts/core/tool_registry.py` PROFILE_TOOLS
3. Update `scripts/cli/wizard.py` PROFILES
4. Update relevant Dockerfile variants
5. Update `versions.yaml` with tool metadata
6. Update this document

**CI enforces consistency** - PRs will fail if sources don't match.

---

## See Also

- [MANUAL_INSTALLATION.md](MANUAL_INSTALLATION.md) - Detailed installation guide
- [VERSION_MANAGEMENT.md](VERSION_MANAGEMENT.md) - Tool version management
- [USER_GUIDE.md](USER_GUIDE.md) - Complete usage reference
- [DOCKER_README.md](DOCKER_README.md) - Docker deep-dive

---

**Last Updated:** December 2025 | **JMo Security v1.0.0**
