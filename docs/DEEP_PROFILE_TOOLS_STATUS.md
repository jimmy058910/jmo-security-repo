# Deep Profile Tools Status & Installation Guide

**Document Version:** 1.0
**Date:** 2025-10-16
**JMo Security Version:** v0.5.1

## Overview

The **deep scan profile** is designed to use **11 comprehensive security tools** for maximum coverage. This document explains the status of each tool, installation methods, and why some tools may be missing in certain environments.

---

## Tool Matrix

| # | Tool | Category | Status | Notes |
|---|------|----------|--------|-------|
| 1 | **trufflehog** | Secrets (verified) | ✅ Installed | Pre-built binary, easy install |
| 2 | **noseyparker** | Secrets (comprehensive) | ✅ Installed | Pre-built binary, musl build |
| 3 | **semgrep** | SAST (multi-language) | ✅ Installed | Python package via pip |
| 4 | **bandit** | SAST (Python-specific) | ✅ Installed | Python package via pip |
| 5 | **syft** | SBOM generator | ✅ Installed | Pre-built binary, easy install |
| 6 | **trivy** | SCA/Vulnerabilities | ✅ Installed | Pre-built binary, easy install |
| 7 | **checkov** | IaC policy-as-code | ✅ Installed | Python package via pip |
| 8 | **hadolint** | Dockerfile best practices | ✅ Installed | Pre-built binary, easy install |
| 9 | **zap** | DAST (web security) | ⚠️ Docker only | Requires Java + 500MB download |
| 10 | **falcoctl** | Runtime security (static) | ⚠️ Docker only | CLI tool for rule validation |
| 11 | **afl++** | Fuzzing (coverage-guided) | ⚠️ Docker only | Requires compilation from source |

**Legend:**
- ✅ **Installed**: Tool is easy to install and works in all environments
- ⚠️ **Docker only**: Tool requires complex setup, recommended via Docker image

---

## Why Are Some Tools "Docker Only"?

### ZAP (OWASP Zed Attack Proxy)

**Requirements:**
- Java Runtime Environment (JRE 11+)
- 500MB download (includes GUI, add-ons)
- Complex PATH configuration

**Installation Complexity:** High
**Build Time:** ~2 minutes (download)

**Why Docker Only:**
- Most users don't have Java installed
- Large download impacts local environment
- Docker image pre-packages Java + ZAP

**Manual Installation (if needed):**
```bash
# Ubuntu/Debian
sudo apt-get install openjdk-11-jre-headless wget
ZAP_VERSION="2.15.0"
wget "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz"
tar -xzf ZAP_${ZAP_VERSION}_Linux.tar.gz -C /opt
sudo ln -s /opt/ZAP_${ZAP_VERSION}/zap.sh /usr/local/bin/zap
```

---

### Falco (Runtime Security)

**Requirements:**
- Linux kernel modules (eBPF or kernel driver)
- Kernel headers matching running kernel
- Root access for module loading

**Installation Complexity:** Very High
**Build Time:** N/A (kernel-dependent)

**Why Docker Only (falcoctl variant):**
- Full Falco requires kernel modules incompatible with WSL/macOS
- Designed for Kubernetes/container runtime environments
- Docker image includes **falcoctl** (CLI tool for static rule validation)
- Runtime scanning requires Falco DaemonSet on K8s cluster

**What We Install:**
- ✅ **falcoctl**: CLI tool for rule management and static analysis
- ❌ **falco daemon**: Runtime monitoring (requires kernel modules)

**Full Falco Installation (K8s only):**
```bash
# Use Falco Helm chart for production K8s deployments
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco
```

**falcoctl Installation (static analysis):**
```bash
FALCOCTL_VERSION="0.11.0"
FALCOCTL_ARCH="amd64"  # or arm64
curl -sSL "https://github.com/falcosecurity/falcoctl/releases/download/v${FALCOCTL_VERSION}/falcoctl_${FALCOCTL_VERSION}_linux_${FALCOCTL_ARCH}.tar.gz" \
  -o /tmp/falcoctl.tar.gz
tar -xzf /tmp/falcoctl.tar.gz -C /usr/local/bin falcoctl
chmod +x /usr/local/bin/falcoctl
```

---

### AFL++ (American Fuzzy Lop)

**Requirements:**
- C/C++ compiler (gcc/clang)
- LLVM development libraries
- Build tools (make, autoconf)
- 200MB+ disk space for source + build artifacts

**Installation Complexity:** Very High
**Build Time:** ~10-15 minutes (compilation from source)

**Why Docker Only:**
- Requires compilation from source (no pre-built binaries)
- Long build time impacts developer experience
- Complex dependencies (LLVM, clang, build-essential)
- Docker image pre-compiles AFL++ at build time

**Manual Installation (if needed):**
```bash
# Ubuntu/Debian
sudo apt-get install build-essential clang llvm

AFL_VERSION="4.21c"
curl -sSL "https://github.com/AFLplusplus/AFLplusplus/archive/refs/tags/v${AFL_VERSION}.tar.gz" \
  -o /tmp/aflplusplus.tar.gz
tar -xzf /tmp/aflplusplus.tar.gz -C /tmp
cd /tmp/AFLplusplus-${AFL_VERSION}
make -j$(nproc)
sudo make install
```

**Build Time:** 10-15 minutes on modern hardware

---

## Recommended Setup by Use Case

### Local Development (8 tools)

**Best for:** Quick scans, pre-commit hooks, local development

**Tools:** trufflehog, noseyparker, semgrep, bandit, syft, trivy, checkov, hadolint (8/11)

**Installation:**
```bash
# Install via package manager (recommended)
pip install jmo-security

# Or use development setup script
make tools  # Installs 8/11 tools automatically
```

**Why This Works:**
- Fast installation (< 5 minutes)
- No compilation required
- Works on WSL, macOS, Linux
- Covers 95% of security use cases

---

### Docker Mode (11 tools)

**Best for:** CI/CD pipelines, comprehensive audits, consistent environments

**Tools:** All 11 tools included

**Usage:**
```bash
# Pull pre-built image (recommended)
docker pull ghcr.io/jimmy058910/jmo-security:v0.5.1-full

# Run deep scan
docker run --rm \
  -v $(pwd):/repo:ro \
  -v $(pwd)/results:/results \
  ghcr.io/jimmy058910/jmo-security:v0.5.1-full \
  ci --repo /repo --profile-name deep --results-dir /results
```

**Why This Works:**
- All 11 tools pre-installed and verified
- Consistent environment across teams
- No local installation required
- Works on any Docker-capable system

---

### Kubernetes/Production (11 tools + Falco daemon)

**Best for:** Production security monitoring, runtime threat detection

**Tools:** All 11 tools + Falco DaemonSet for runtime monitoring

**Setup:**
```bash
# 1. Install JMo Security for static scanning
kubectl create configmap jmo-security \
  --from-file=jmo.yml=./jmo.yml

# 2. Install Falco for runtime monitoring
helm install falco falcosecurity/falco \
  --set driver.kind=ebpf \
  --set collectors.enabled=true

# 3. Run JMo Security scans as CronJob
kubectl apply -f k8s/jmo-security-cronjob.yaml
```

**Why This Works:**
- Falco daemon monitors runtime threats (syscalls, network, file access)
- JMo Security provides static analysis of images/manifests
- Combined coverage: SAST + SCA + IaC + DAST + runtime monitoring

---

## Tool Coverage Matrix

### Security Domains Covered by Each Tool

| Domain | Tools | Count | Notes |
|--------|-------|-------|-------|
| **Secrets Detection** | trufflehog, noseyparker | 2 | Dual scanners reduce false positives |
| **SAST (Static Application Security Testing)** | semgrep, bandit | 2 | Multi-language + Python-specific |
| **SBOM (Software Bill of Materials)** | syft | 1 | Generates SBOM for dependency tracking |
| **SCA (Software Composition Analysis)** | trivy | 1 | Vulnerability scanning for dependencies |
| **IaC (Infrastructure as Code)** | checkov | 1 | Policy-as-code for Terraform, K8s, etc. |
| **Dockerfile Linting** | hadolint | 1 | Best practices for container images |
| **DAST (Dynamic Application Security Testing)** | zap | 1 | Web application security scanning |
| **Runtime Security** | falcoctl (static), falco (runtime) | 1+1 | Rule validation + runtime monitoring |
| **Fuzzing** | afl++ | 1 | Coverage-guided fuzzing for C/C++ |

**Total Coverage:** 9 security domains, 11 tools

---

## Deep Profile Behavior

### Tool Selection Logic

The deep profile (`--profile-name deep`) is configured in `jmo.yml`:

```yaml
deep:
  tools: [trufflehog, noseyparker, semgrep, bandit, syft, trivy, checkov, hadolint, zap, falco, afl++]
  threads: 2
  timeout: 900
  retries: 1
```

### Graceful Degradation

**Important:** The deep profile **does NOT fail** if tools are missing. Instead:

1. **Scan Phase:**
   - Attempts to run all 11 tools
   - Skips tools that aren't installed (with warning log)
   - Continues with available tools
   - Writes empty stubs for missing tools

2. **Report Phase:**
   - Aggregates findings from all tools that ran successfully
   - Enriches with compliance frameworks (OWASP, CWE, CIS, NIST, PCI DSS, MITRE ATT&CK)
   - Generates complete reports even if some tools missing

**Example:**
```bash
# Local environment (8/11 tools)
jmo ci --repo myproject --profile-name deep

# Output:
# INFO: Scanning with 8/11 tools (zap, falco, afl++ not installed)
# INFO: Found 245 findings across 8 tools
# INFO: Compliance enrichment: 245/245 (100%)
```

---

## Installation Scripts

### Quick Install (8 tools, 5 minutes)

```bash
#!/bin/bash
# Install 8 core tools for local development

# Python tools
pip install bandit semgrep checkov

# Binary tools
make tools  # Uses scripts/dev/install_tools.sh
```

### Full Install (11 tools, 20 minutes)

```bash
#!/bin/bash
# Install all 11 tools (includes compilation)

# Core 8 tools
make tools

# ZAP (requires Java)
sudo apt-get install openjdk-11-jre-headless
./scripts/dev/install_zap.sh

# Falcoctl
./scripts/dev/install_falcoctl.sh

# AFL++ (requires compilation)
./scripts/dev/install_aflplusplus.sh
```

### Docker Build (11 tools, 15-20 minutes)

```bash
#!/bin/bash
# Build Docker image with all 11 tools

docker build -t jmo-security:v0.5.1-full -f Dockerfile .
```

---

## FAQ

### Q: Why only 6 tools ran when I used deep profile?

**A:** You're running in a local environment where only the 8 core tools are installed. The deep profile gracefully handles missing tools. Use Docker for all 11 tools:

```bash
docker run --rm -v $(pwd):/repo:ro ghcr.io/jimmy058910/jmo-security:v0.5.1-full \
  ci --repo /repo --profile-name deep
```

### Q: Do I need all 11 tools?

**A:** No. The 8 core tools (trufflehog, noseyparker, semgrep, bandit, syft, trivy, checkov, hadolint) cover 95% of security use cases. ZAP, Falco, and AFL++ are for specialized scenarios:
- **ZAP:** Dynamic web application testing
- **Falco:** Runtime threat detection (K8s/containers)
- **AFL++:** Fuzzing C/C++ binaries

### Q: Can I install just ZAP/Falco/AFL++ locally?

**A:** Yes, but it's not recommended due to complexity. Use Docker instead:
- **ZAP:** Requires Java + 500MB download
- **Falco:** Requires kernel modules (K8s only for full runtime)
- **AFL++:** Requires 10-15 minute compilation

### Q: Will the deep profile fail if tools are missing?

**A:** No. The scan continues with available tools and generates reports normally. You'll see warning logs like:
```
WARN: Tool 'zap' not found, skipping
WARN: Tool 'falco' not found, skipping
INFO: Scanning with 8/11 tools
```

### Q: How do I verify which tools are installed?

```bash
# Check all tools
jmo --verify-tools

# Or use make target
make verify-env
```

### Q: Should I use balanced or deep profile?

| Profile | Tools | Duration | Use Case |
|---------|-------|----------|----------|
| **fast** | 3 | 5-8 min | Pre-commit, quick validation |
| **balanced** | 7 | 15-20 min | CI/CD, regular audits |
| **deep** | 11 | 30-60 min | Security audits, compliance, pre-release |

**Recommendation:**
- **Development:** Use `balanced` (7 tools, 15-20 min)
- **CI/CD:** Use `balanced` with Docker for consistency
- **Security Audits:** Use `deep` with Docker for maximum coverage

---

## Troubleshooting

### Tool Not Found Errors

**Symptom:**
```
ERROR: Tool 'zap' not found in PATH
```

**Solution:**
Either install the tool manually or use Docker:
```bash
docker run --rm -v $(pwd):/repo:ro ghcr.io/jimmy058910/jmo-security:v0.5.1-full \
  ci --repo /repo --profile-name deep
```

### Docker Build Fails on Falco

**Symptom:**
```
ERROR: falco tarball not in gzip format
```

**Solution:**
Use the fixed Dockerfile (v0.5.1+) which installs falcoctl instead of full Falco.

### AFL++ Compilation Fails

**Symptom:**
```
ERROR: make failed during AFL++ installation
```

**Solution:**
Install missing build dependencies:
```bash
sudo apt-get install build-essential clang llvm
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| v0.5.1 | 2025-10-16 | Fixed Falco installation (falcoctl), added compliance integration |
| v0.5.0 | 2025-10-15 | Tool consolidation, removed gitleaks/tfsec/osv-scanner |
| v0.4.0 | 2025-10-01 | Added deep profile with 11 tools |

---

*Last Updated: 2025-10-16*
*Maintainer: James Moceri <general@jmogaming.com>*
