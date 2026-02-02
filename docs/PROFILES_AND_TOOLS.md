# Scan Profiles and Tools Reference

> **Canonical source for JMo Security scan profiles and tool definitions.**

This document is the authoritative reference for which tools are included in each scan profile. All profile definitions across the codebase (jmo.yml, tool_registry.py, wizard_flows/profile_config.py, Docker variants) MUST match this document.

## Table of Contents

- [Quick Reference](#quick-reference)
- [Profile Overview](#profile-overview)
- [Profile Tool Lists](#profile-tool-lists)
- [Tool Categories](#tool-categories)
- [Tool Selection Philosophy](#tool-selection-philosophy)
- [Content-Triggered Tool Execution](#content-triggered-tool-execution)
- [Scan Type Tool Matrix](#scan-type-tool-matrix)
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

**Tools included:** Balanced profile + backup secrets scanning (Nosey Parker), Python SAST (Bandit), malware detection (YARA), runtime security (Falco), fuzzing (AFL++), mobile security (MobSF), API security (Akto), system hardening (Lynis), and dependency vulnerability analysis (OWASP Dependency-Check).

> **First-Run Warning:** The `dependency-check` tool downloads the NIST NVD database (~2GB) on its first run, which can take **30-90 minutes** depending on network speed and NIST API rate limits. Subsequent runs use the cached database and complete in **2-5 minutes**.
>
> For faster repeat scans in Docker, mount a persistent volume:
> ```bash
> docker run -v dep-check-cache:/root/.dependency-check -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:deep scan
> ```

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
  # Additional (5)
  - prowler         # Multi-cloud CSPM (AWS/Azure/GCP/K8s)
  - kubescape       # Kubernetes security (NSA/CISA)
  - grype           # Vulnerability scanner (Anchore DB)
  - bearer          # Data privacy/SAST (GDPR/CCPA)
  - horusec         # Multi-language SAST (18+ languages)
  # Note: dependency-check moved to deep profile only (slow first-run NVD download)
```

### Balanced Profile (18 tools)

```yaml
balanced:
  # Slim profile (13)
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
  # Additional (4)
  - zap             # OWASP ZAP - DAST
  - scancode        # License/copyright scanning
  - cdxgen          # CycloneDX SBOM (30+ languages)
  - gosec           # Go security analyzer
  # Note: dependency-check moved to deep profile only (slow first-run NVD download)
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
  - dependency-check  # OWASP SCA - deep only (30-40min first-run NVD download)
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

## Tool Selection Philosophy

JMo Security intentionally includes **overlapping tools** for defense-in-depth coverage. This section explains why certain tools exist alongside others that may seem duplicative.

### Why Multiple Secrets Scanners?

| Tool | Unique Value | Trade-off |
|------|--------------|-----------|
| **TruffleHog** | 800+ detectors, **API verification** (confirms secrets are live) | Higher false positive rate without verification |
| **Nosey Parker** | 98.5% precision with ML filtering, 10x faster | No API verification, ~200 detectors |
| **Semgrep-Secrets** | Code context awareness (understands variable assignments) | Pattern-based, no verification |

**Rationale:** TruffleHog catches the most secrets; Nosey Parker has fewer false positives; Semgrep-Secrets understands code structure. Running all three in deep profile maximizes detection while cross-tool deduplication removes duplicates.

### Why Multiple SCA Scanners?

| Tool | Database | Unique Value |
|------|----------|--------------|
| **Trivy** | CVE/NVD + vendor advisories | Broadest coverage, multi-target (code, containers, IaC) |
| **Grype** | Anchore vulnerability DB | Different data sources, catches CVEs Trivy may miss |
| **Dependency-Check** | OWASP NVD | OWASP compliance reporting, CPE matching |

**Rationale:** Vulnerability databases have different update cycles and coverage. Running multiple SCA tools with different databases reduces blind spots. Cross-tool deduplication (30-40% reduction) prevents duplicate noise.

### Why Multiple SAST Scanners?

| Tool | Strengths | Languages |
|------|-----------|-----------|
| **Semgrep** | Low false positives, fast, community rules | 30+ languages |
| **Horusec** | Different rule engine, catches patterns Semgrep misses | 18+ languages |
| **Bandit** | Deep Python expertise (weak crypto, shell injection) | Python only |
| **Gosec** | Go-specific patterns (race conditions, memory safety) | Go only |
| **Bearer** | Data privacy focus (GDPR/CCPA, PII exposure) | 12+ languages |

**Rationale:** No single SAST tool catches everything. Language-specific tools (Bandit, Gosec) have deeper coverage than polyglot tools. Bearer adds privacy-specific rules that security-focused tools often miss.

### Why Multiple IaC Scanners?

| Tool | Focus Area |
|------|------------|
| **Checkov** | Broadest policy coverage (1000+ rules), multi-framework |
| **Trivy** | Misconfiguration scanning integrated with vulnerability scanning |
| **Kubescape** | NSA/CISA hardening guidelines, K8s-specific |
| **Prowler** | Cloud provider native (AWS/Azure/GCP CIS benchmarks) |

**Rationale:** Checkov provides breadth; specialized tools (Kubescape for K8s, Prowler for cloud) provide depth in their domains.

---

## Content-Triggered Tool Execution

Some tools only execute when specific content is detected in the target repository. This reduces scan time and avoids irrelevant findings.

### Conditional Execution Matrix

| Tool | Trigger Condition | Behavior When Not Triggered |
|------|-------------------|----------------------------|
| **MobSF** | `*.apk` or `*.ipa` files detected | Writes empty stub |
| **Prowler** | `*.tf`, `*.tfvars`, or `cloudformation.yaml` detected | Writes empty stub |
| **ZAP** (repo mode) | HTML, JS, or PHP files detected | Writes empty stub |
| **Trivy-RBAC** | Kubernetes manifests (`*deployment*.yaml`, `*service*.yaml`, `k8s/**/*.yaml`) | Writes empty stub |
| **Falco** | Falco rule files (`*falco*.yaml`, `*falco*.yml`) detected | Writes empty stub |
| **AFL++** | Instrumented binaries (`*-afl`, `*-fuzzer`, `bin/*`, `build/*`) detected | Writes empty stub |
| **Hadolint** | `Dockerfile*` files detected | Writes empty stub |
| **Lynis** | Never runs on repositories (system scanner) | Always writes stub |
| **Akto** | URL targets only (not applicable to repositories) | Not invoked |

### Detection Logic Details

**MobSF (Mobile Security):**

```python
# Scans first mobile app found
mobile_files = list(repo.glob("**/*.apk")) + list(repo.glob("**/*.ipa"))
```

**Prowler (Cloud Security):**

```python
# Only runs if cloud config files exist
cloud_files = (
    list(repo.glob("**/*.tf")) +
    list(repo.glob("**/*.tfvars")) +
    list(repo.glob("**/cloudformation.yaml")) +
    list(repo.glob("**/cloudformation.json"))
)
```

**ZAP (Web Scanning in repo mode):**

```python
# Scans static web files when present
web_files = (
    list(repo.glob("**/*.html")) +
    list(repo.glob("**/*.js")) +
    list(repo.glob("**/*.php"))
)
```

**Trivy-RBAC (Kubernetes):**

```python
# Requires K8s manifests
k8s_manifests = (
    list(repo.glob("**/*deployment*.yaml")) +
    list(repo.glob("**/*service*.yaml")) +
    list(repo.glob("**/k8s/**/*.yaml"))
)
```

### Stub Files

When a tool doesn't run due to missing trigger content, JMo Security writes an empty stub file to:

1. Indicate the tool was considered but not applicable
2. Prevent downstream errors expecting output files
3. Enable consistent reporting across all tools

Stub format:

```json
{
  "tool": "mobsf",
  "status": "skipped",
  "reason": "No applicable files found",
  "findings": []
}
```

---

## Scan Type Tool Matrix

Different target types invoke different subsets of tools. This matrix shows the complete mapping.

### Target Type Overview

| Target Type | CLI Flag | Scanner Module | Tool Count |
|-------------|----------|----------------|------------|
| **Local Repository** | `--repo .` | `repository_scanner.py` | Up to 28 (profile-dependent) |
| **Container Image** | `--image nginx:latest` | `image_scanner.py` | 2 (trivy, syft) |
| **IaC File** | Auto-detected | `iac_scanner.py` | 2 (checkov, trivy) |
| **Web URL/API** | `--url https://...` | `url_scanner.py` | 3 (zap, nuclei, akto) |
| **GitLab Remote** | `--gitlab group/repo` | `gitlab_scanner.py` | All repo tools + image tools |
| **Kubernetes Cluster** | `--k8s` | `k8s_scanner.py` | 1 (trivy k8s mode) |

### Detailed Tool Applicability

#### Local Repository Scan (`jmo scan --repo .`)

**Always Run (if in profile):**

| Category | Tools |
|----------|-------|
| Secrets | trufflehog, noseyparker, semgrep-secrets |
| SAST | semgrep, bandit, gosec, horusec, bearer |
| SCA | trivy, grype, dependency-check |
| SBOM | syft, cdxgen |
| IaC | checkov, checkov-cicd, hadolint, kubescape, prowler* |
| License | scancode |
| Other | shellcheck, yara |

**Conditional (content-triggered):**

| Tool | Requires |
|------|----------|
| prowler | `*.tf`, `cloudformation.yaml` |
| zap | HTML/JS/PHP files |
| trivy-rbac | K8s manifests |
| falco | Falco rule files |
| mobsf | APK/IPA files |
| afl++ | Instrumented binaries |

**Never Run on Repositories:**

| Tool | Reason |
|------|--------|
| lynis | System-level scanner (host OS audit) |
| akto | Requires live API endpoints |

#### Container Image Scan (`jmo scan --image nginx:latest`)

| Tool | Mode | Output |
|------|------|--------|
| **trivy** | `trivy image --scanners vuln,secret,misconfig` | CVEs, secrets, misconfigs |
| **syft** | `syft <image>` | SBOM (CycloneDX/SPDX) |

#### IaC File Scan (auto-detected)

| Tool | Mode | Targets |
|------|------|---------|
| **checkov** | `checkov -f <file>` | Terraform, CloudFormation, K8s, Dockerfile |
| **trivy** | `trivy config <file>` | Misconfigurations |

#### Web URL Scan (`jmo scan --url https://example.com`)

| Tool | Mode | Focus |
|------|------|-------|
| **nuclei** | `nuclei -u <url>` | 4000+ vulnerability templates, CVE probes |
| **zap** | `zap -quickurl <url>` | OWASP DAST, active scanning |
| **akto** | `akto test --url <url>` | OWASP API Top 10 (deep profile only) |

#### GitLab Remote Scan (`jmo scan --gitlab group/repo`)

1. **Clone** repository (shallow, single branch)
2. **Run all repository scanner tools** (same as `--repo`)
3. **Discover container images** from:
   - `Dockerfile` FROM lines
   - `docker-compose.yml` image fields
   - `*.k8s.yaml` container images
4. **Scan discovered images** with trivy + syft
5. **Aggregate results** under `individual-gitlab/<group>_<repo>/`

#### Kubernetes Cluster Scan (`jmo scan --k8s`)

| Tool | Mode | Targets |
|------|------|---------|
| **trivy** | `trivy k8s --all-namespaces all` | Pods, deployments, configmaps, secrets, RBAC |

### Quick Reference: Tool → Target Type

| Tool | Repo | Image | IaC | URL | GitLab | K8s |
|------|:----:|:-----:|:---:|:---:|:------:|:---:|
| trufflehog | ✅ | - | - | - | ✅ | - |
| noseyparker | ✅ | - | - | - | ✅ | - |
| semgrep | ✅ | - | - | - | ✅ | - |
| semgrep-secrets | ✅ | - | - | - | ✅ | - |
| bandit | ✅ | - | - | - | ✅ | - |
| gosec | ✅ | - | - | - | ✅ | - |
| horusec | ✅ | - | - | - | ✅ | - |
| bearer | ✅ | - | - | - | ✅ | - |
| trivy | ✅ | ✅ | ✅ | - | ✅ | ✅ |
| grype | ✅ | - | - | - | ✅ | - |
| dependency-check | ✅ | - | - | - | ✅ | - |
| syft | ✅ | ✅ | - | - | ✅ | - |
| cdxgen | ✅ | - | - | - | ✅ | - |
| checkov | ✅ | - | ✅ | - | ✅ | - |
| checkov-cicd | ✅ | - | - | - | ✅ | - |
| hadolint | ✅* | - | - | - | ✅* | - |
| kubescape | ✅ | - | - | - | ✅ | - |
| prowler | ✅* | - | - | - | ✅* | - |
| trivy-rbac | ✅* | - | - | - | ✅* | - |
| scancode | ✅ | - | - | - | ✅ | - |
| shellcheck | ✅ | - | - | - | ✅ | - |
| yara | ✅ | - | - | - | ✅ | - |
| falco | ✅* | - | - | - | ✅* | - |
| nuclei | - | - | - | ✅ | - | - |
| zap | ✅* | - | - | ✅ | ✅* | - |
| akto | - | - | - | ✅ | - | - |
| mobsf | ✅* | - | - | - | ✅* | - |
| afl++ | ✅* | - | - | - | ✅* | - |
| lynis | - | - | - | - | - | - |

**Legend:** ✅ = Always applicable | ✅* = Content-triggered | - = Not applicable

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
| **wizard_flows/profile_config.py** | 8 | 14 | 18 | 28 | Must match |
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
3. Update `scripts/cli/wizard_flows/profile_config.py` PROFILES
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

**Last Updated:** January 2026 | **JMo Security v1.0.0**
