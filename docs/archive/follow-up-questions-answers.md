# Follow-Up Questions - Comprehensive Answers

## Question 1: Risk Metadata - Should we Add NIST?

**Answer:** ✅ **YES - Added to Schema**

### What I Did

Added NIST SP 800-53 controls to the CommonFinding schema (line 73):

```json
"nist": {
  "type": "array",
  "items": { "type": "string" },
  "description": "NIST SP 800-53 controls (e.g., ['AC-6', 'IA-5'])"
}
```

### Why NIST Matters

**NIST SP 800-53** is the standard for federal/government compliance (FedRAMP, FISMA, etc.):

- **AC-6**: Least Privilege (privilege escalation issues)
- **IA-5**: Authenticator Management (hardcoded credentials, weak passwords)
- **SC-7**: Boundary Protection (exposed services, network security)
- **SI-10**: Information Input Validation (injection vulnerabilities)
- **CM-6**: Configuration Settings (misconfigurations)

### Current Risk Metadata

```json
"risk": {
  "cwe": ["CWE-269", "CWE-798"],           // Weakness classification
  "owasp": ["A04:2021", "A07:2021"],       // OWASP Top 10 mapping
  "nist": ["AC-6", "IA-5"],                // NIST controls (NEW!)
  "confidence": "HIGH",                     // Tool confidence
  "likelihood": "HIGH",                     // Exploitation likelihood
  "impact": "HIGH"                          // Business impact
}
```

### Common NIST Mappings for Security Findings

| Finding Type | NIST Control | Description |
|--------------|--------------|-------------|
| Hardcoded credentials | IA-5(1) | Authenticator Management |
| Privilege escalation | AC-6 | Least Privilege |
| SQL injection | SI-10 | Input Validation |
| Missing encryption | SC-8 | Transmission Confidentiality |
| Exposed services | SC-7 | Boundary Protection |
| Missing patches | SI-2 | Flaw Remediation |
| Weak crypto | SC-13 | Cryptographic Protection |
| Missing logging | AU-12 | Audit Generation |
| Default passwords | IA-5(1) | Authenticator Management |
| Insecure config | CM-6 | Configuration Settings |

### Implementation Strategy

**Phase 1: Schema Update** ✅ DONE
- Added `nist` field to CommonFinding schema

**Phase 2: Adapter Enhancement** (Next Steps)
- Update adapters to extract NIST mappings from tool outputs
- Add fallback NIST mapping for tools without native support

**Phase 3: Reporting Enhancement**
- Display NIST controls in dashboard (e.g., "🛡️ AC-6, IA-5")
- Add NIST control filter in dashboard
- Include NIST summary in SUMMARY.md

**Phase 4: Compliance Reporting** (Future)
- Generate NIST SP 800-53 compliance report
- Map findings to NIST control families
- Track control coverage and gaps

### Example Adapter Code (Semgrep)

```python
def load_semgrep(path: Path) -> List[Dict[str, Any]]:
    # ... existing code ...

    # Extract NIST mappings from Semgrep metadata
    nist_controls = []
    owasp_cats = extra.get("metadata", {}).get("owasp", [])

    # Map OWASP to NIST (example)
    if "A01:2021" in owasp_cats:  # Broken Access Control
        nist_controls.extend(["AC-3", "AC-6"])
    if "A02:2021" in owasp_cats:  # Cryptographic Failures
        nist_controls.extend(["SC-8", "SC-13"])
    if "A03:2021" in owasp_cats:  # Injection
        nist_controls.extend(["SI-10"])

    finding["risk"] = {
        "cwe": cwe_list,
        "owasp": owasp_cats,
        "nist": nist_controls,  # NEW!
        "confidence": extra.get("metadata", {}).get("confidence", "MEDIUM").upper(),
    }
```

### Tool Support for NIST Mappings

| Tool | Native NIST Support | Implementation |
|------|---------------------|----------------|
| Semgrep | ❌ No | Map from OWASP/CWE |
| Trivy | ❌ No | Map from CVE/CWE |
| Checkov | ✅ Yes (some checks) | Extract from metadata |
| Bandit | ❌ No | Map from CWE |
| Gitleaks | ❌ No | Hardcode by rule type |

### Benefits

1. **Government Compliance**: Essential for FedRAMP, FISMA, CMMC certifications
2. **Unified Framework**: NIST is widely adopted in enterprise security
3. **Risk Prioritization**: Map findings to control requirements for remediation planning
4. **Audit Trail**: Demonstrate control coverage for compliance audits
5. **Policy Enforcement**: Validate security policies align with NIST controls

---

## Question 2: Docker Image Optimization (Size/Performance)

**Answer:** Yes! Here's a comprehensive optimization strategy.

### Current Docker Image Sizes

| Variant | Current Size | Target Size | Optimization Potential |
|---------|--------------|-------------|------------------------|
| Full | ~1.5GB | ~800MB | 700MB (47% reduction) |
| Slim | ~1.1GB | ~600MB | 500MB (45% reduction) |
| Alpine | N/A | ~400MB | New variant |

### Optimization Strategies

#### Strategy 1: Multi-Stage Builds ⭐ HIGH IMPACT

**Current:** Single-stage build (copies everything)
**Proposed:** Multi-stage with builder + runtime

```dockerfile
# Stage 1: Builder - Install all tools
FROM ubuntu:22.04 AS builder

# Install dependencies, build tools
RUN apt-get update && apt-get install -y curl ca-certificates python3-pip
RUN pip install bandit semgrep checkov
# ... install all binaries ...

# Stage 2: Runtime - Copy only binaries
FROM ubuntu:22.04

# Copy ONLY binaries from builder
COPY --from=builder /usr/local/bin/gitleaks /usr/local/bin/
COPY --from=builder /usr/local/bin/trivy /usr/local/bin/
# ... etc ...

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy JMo source
COPY . /opt/jmo-security/
RUN pip install --no-cache-dir -e /opt/jmo-security/
```

**Expected Savings:** ~300-400MB (removed build tools, temp files)

---

#### Strategy 2: Layer Optimization ⭐ MEDIUM IMPACT

**Current:** Each tool in separate RUN layer
**Proposed:** Combine related installations

```dockerfile
# Before (separate layers)
RUN install_gitleaks
RUN install_trufflehog
RUN install_semgrep

# After (combined layer)
RUN set -ex && \
    install_gitleaks && \
    install_trufflehog && \
    install_semgrep && \
    rm -rf /tmp/* /var/cache/*
```

**Expected Savings:** ~100-200MB (reduced layer overhead)

---

#### Strategy 3: Distroless Base ⭐ HIGH IMPACT

**Current:** Ubuntu 22.04 base (~80MB)
**Proposed:** Google Distroless Python (~50MB)

```dockerfile
FROM gcr.io/distroless/python3-debian12

# Copy pre-built binaries
COPY --from=builder /usr/local/bin/* /usr/local/bin/
COPY --from=builder /opt/jmo-security /opt/jmo-security

ENV PYTHONPATH=/opt/jmo-security
ENTRYPOINT ["python3", "/opt/jmo-security/scripts/cli/jmo.py"]
```

**Benefits:**
- Smaller size (~50MB vs 80MB base)
- No shell (improved security)
- No package manager (reduced attack surface)

**Tradeoffs:**
- Debugging harder (no shell access)
- Requires static binaries

**Expected Savings:** ~30MB + improved security posture

---

#### Strategy 4: Alpine Variant ⭐ MEDIUM IMPACT

**Current:** Only Ubuntu-based images
**Proposed:** Add Alpine variant (minimal Linux)

```dockerfile
FROM alpine:3.19

# Install minimal dependencies
RUN apk add --no-cache python3 py3-pip ca-certificates

# Install tools (use musl-compatible binaries)
RUN install_tools_alpine

# Install JMo
COPY . /opt/jmo-security/
RUN pip install --no-cache-dir -e /opt/jmo-security/
```

**Expected Size:** ~400MB (vs 1.5GB full)

**Tradeoffs:**
- Some tools may need musl builds
- Compatibility testing required

---

#### Strategy 5: Tool Dependency Analysis 🔍 LOW IMPACT

**Current:** Install all tools unconditionally
**Proposed:** Lazy-load tools based on profile

**Full Image:** All 11 tools (~1.5GB)
**Balanced Image:** 7 core tools (~900MB)
**Fast Image:** 4 essential tools (~600MB)

```dockerfile
# Dockerfile.fast
FROM ubuntu:22.04
RUN install_gitleaks install_semgrep install_syft install_trivy
# Skip: noseyparker, trufflehog, checkov, tfsec, hadolint, bandit, osv-scanner

# Dockerfile.balanced (default)
FROM ubuntu:22.04
RUN install_core_tools  # 7 most common tools

# Dockerfile.full
FROM ubuntu:22.04
RUN install_all_tools  # All 11 tools
```

**Expected Savings:**
- Fast: 900MB reduction
- Balanced: 600MB reduction

---

#### Strategy 6: Cache Optimization 🚀 PERFORMANCE

**Current:** No caching between scans
**Proposed:** Persistent Trivy DB cache

```dockerfile
# Create cache directory
RUN mkdir -p /var/cache/trivy

# Pre-download Trivy DB at build time
RUN trivy image --download-db-only

# In runtime, mount cache volume:
docker run -v trivy-cache:/var/cache/trivy jmo-security:latest scan ...
```

**Benefits:**
- Faster scans (~30s DB download eliminated)
- Consistent DB version across scans
- Reduced network bandwidth

---

### Recommended Implementation Plan

**Phase 1: Quick Wins (Next Release v0.5.0)**
1. ✅ Multi-stage builds (Strategy 1) - 300MB savings
2. ✅ Layer optimization (Strategy 2) - 100MB savings
3. ✅ Cleanup temp files aggressively

**Expected Result:** Full image ~1.0GB (500MB reduction)

**Phase 2: Advanced Optimization (v0.6.0)**
1. Add Alpine variant (Strategy 4)
2. Add Distroless variant (Strategy 3)
3. Implement Trivy cache (Strategy 6)

**Expected Result:**
- Full: ~800MB
- Alpine: ~400MB
- Distroless: ~600MB

**Phase 3: Profile-Based Images (v0.7.0)**
1. Build separate images per profile (Strategy 5)
2. Add image variant matrix to CI/CD

**Expected Result:**
- fast: ~600MB
- balanced: ~900MB
- full: ~800MB

### Dockerfile Template (Multi-Stage Optimized)

```dockerfile
# ==================================
# Stage 1: Builder
# ==================================
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive
ARG TARGETARCH

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install security tools
RUN set -ex && \
    install_gitleaks && \
    install_trufflehog && \
    install_semgrep && \
    install_syft && \
    install_trivy && \
    install_hadolint && \
    install_tfsec && \
    install_osv_scanner && \
    install_noseyparker && \
    rm -rf /tmp/* /var/cache/* /var/lib/apt/lists/*

# Install Python tools
RUN pip install --no-cache-dir \
    bandit==1.7.10 \
    semgrep==1.94.0 \
    checkov==3.2.255

# ==================================
# Stage 2: Runtime
# ==================================
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install ONLY runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy binaries from builder
COPY --from=builder /usr/local/bin/gitleaks /usr/local/bin/
COPY --from=builder /usr/local/bin/trufflehog /usr/local/bin/
COPY --from=builder /usr/local/bin/semgrep /usr/local/bin/
# ... (all other binaries)

# Copy Python packages
COPY --from=builder /usr/local/lib/python3.10/dist-packages /usr/local/lib/python3.10/dist-packages

# Copy JMo source
COPY . /opt/jmo-security/
WORKDIR /scan
RUN cp /opt/jmo-security/jmo.yml /scan/jmo.yml

# Install JMo
RUN cd /opt/jmo-security && \
    pip install --no-cache-dir -e ".[reporting]"

ENTRYPOINT ["jmo"]
CMD ["--help"]
```

---

## Question 3: How to Keep Versions Consistent?

**Answer:** Comprehensive version management strategy with automation.

### Root Cause Analysis

**Problem:** Docker Trivy v0.58.1 vs Native v0.67.2 (9 weeks outdated)

**Why This Happened:**
1. ❌ Manual version pinning in Dockerfile
2. ❌ No automated version checks
3. ❌ No native vs Docker comparison tests
4. ❌ No version update alerts

### Solution: Multi-Layered Version Management

#### Layer 1: Centralized Version File ⭐ FOUNDATION

Create `versions.yaml` as single source of truth:

```yaml
# versions.yaml - Central tool version registry
# Updated: 2025-10-15
# Auto-checked by CI weekly

tools:
  gitleaks:
    version: "8.21.2"
    release_url: "https://github.com/gitleaks/gitleaks/releases"
    update_frequency: "monthly"

  trivy:
    version: "0.67.2"
    release_url: "https://github.com/aquasecurity/trivy/releases"
    update_frequency: "weekly"  # CVE database updates frequently
    critical: true              # Flag for security-critical tools

  semgrep:
    version: "1.94.0"
    release_url: "https://github.com/semgrep/semgrep/releases"
    update_frequency: "monthly"

  # ... all 11 tools ...

# Python packages
python_packages:
  bandit: "1.7.10"
  checkov: "3.2.255"
  semgrep: "1.94.0"
```

**Usage in Dockerfile:**

```dockerfile
# Auto-generated from versions.yaml - DO NOT EDIT MANUALLY
ARG GITLEAKS_VERSION=8.21.2
ARG TRIVY_VERSION=0.67.2
ARG SEMGREP_VERSION=1.94.0

RUN TRIVY_VERSION="${TRIVY_VERSION}" && \
    curl -sSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/..."
```

---

#### Layer 2: Automated Version Checker CI Job 🤖 AUTOMATION

**.github/workflows/version-check.yml:**

```yaml
name: Version Consistency Check

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday
  workflow_dispatch:
  pull_request:
    paths:
      - 'Dockerfile'
      - 'versions.yaml'
      - 'scripts/dev/install_tools.sh'

jobs:
  check-versions:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install tools natively
        run: make tools

      - name: Get native versions
        id: native
        run: |
          echo "gitleaks=$(gitleaks version | grep -oP 'v\K[\d.]+')" >> $GITHUB_OUTPUT
          echo "trivy=$(trivy --version | grep -oP 'Version: \K[\d.]+')" >> $GITHUB_OUTPUT
          echo "semgrep=$(semgrep --version)" >> $GITHUB_OUTPUT

      - name: Get Docker versions
        id: docker
        run: |
          docker build -t test .
          echo "trivy=$(docker run --rm --entrypoint trivy test --version | grep -oP 'Version: \K[\d.]+')" >> $GITHUB_OUTPUT

      - name: Compare versions
        run: |
          if [ "${{ steps.native.outputs.trivy }}" != "${{ steps.docker.outputs.trivy }}" ]; then
            echo "❌ Trivy version mismatch!"
            echo "Native: ${{ steps.native.outputs.trivy }}"
            echo "Docker: ${{ steps.docker.outputs.trivy }}"
            exit 1
          fi

      - name: Check for updates
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const yaml = require('js-yaml');

            const versions = yaml.load(fs.readFileSync('versions.yaml', 'utf8'));

            for (const [tool, config] of Object.entries(versions.tools)) {
              if (config.critical) {
                // Check GitHub releases for new versions
                const { data } = await github.rest.repos.getLatestRelease({
                  owner: config.release_url.split('/')[3],
                  repo: config.release_url.split('/')[4],
                });

                if (data.tag_name.replace('v', '') !== config.version) {
                  console.log(`⚠️ ${tool} update available: ${config.version} → ${data.tag_name}`);
                  // Create issue if critical tool is outdated
                  if (config.critical) {
                    await github.rest.issues.create({
                      owner: context.repo.owner,
                      repo: context.repo.repo,
                      title: `[Security] Update ${tool} to ${data.tag_name}`,
                      body: `Critical security tool ${tool} has a new release.\n\nCurrent: ${config.version}\nLatest: ${data.tag_name}\n\nRelease notes: ${data.html_url}`,
                      labels: ['security', 'dependencies', 'automated'],
                    });
                  }
                }
              }
            }
```

---

#### Layer 3: Dependabot Configuration 🤖 AUTOMATION

**.github/dependabot.yml:**

```yaml
version: 2
updates:
  # Python dependencies
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    labels:
      - "dependencies"
      - "python"

  # Docker base images
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
    labels:
      - "dependencies"
      - "docker"

  # GitHub Actions
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    labels:
      - "dependencies"
      - "ci"
```

**Note:** Dependabot doesn't track custom binary installations (gitleaks, trivy, etc.), so we need custom automation (Layer 2).

---

#### Layer 4: Integration Test for Version Parity 🧪 TESTING

**tests/integration/test_version_consistency.py:**

```python
import subprocess
import pytest
import re

def get_native_version(tool):
    """Get version of natively installed tool."""
    try:
        result = subprocess.run([tool, "--version"], capture_output=True, text=True, check=True)
        # Parse version from output (tool-specific regex)
        version = re.search(r'(\d+\.\d+\.\d+)', result.stdout or result.stderr)
        return version.group(1) if version else None
    except Exception as e:
        return None

def get_docker_version(tool):
    """Get version of tool inside Docker image."""
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", "--entrypoint", tool, "jmo-security:test", "--version"],
            capture_output=True, text=True, check=True
        )
        version = re.search(r'(\d+\.\d+\.\d+)', result.stdout or result.stderr)
        return version.group(1) if version else None
    except Exception as e:
        return None

@pytest.mark.parametrize("tool", [
    "gitleaks", "trivy", "semgrep", "syft", "hadolint", "tfsec", "osv-scanner"
])
def test_version_parity(tool):
    """Verify native and Docker tool versions match."""
    native = get_native_version(tool)
    docker = get_docker_version(tool)

    assert native is not None, f"{tool} not installed natively"
    assert docker is not None, f"{tool} not found in Docker image"
    assert native == docker, f"{tool} version mismatch: native={native}, docker={docker}"

def test_trivy_db_freshness():
    """Verify Trivy vulnerability database is recent (< 7 days old)."""
    result = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "trivy", "jmo-security:test", "version", "--format", "json"],
        capture_output=True, text=True, check=True
    )

    import json
    from datetime import datetime, timedelta

    data = json.loads(result.stdout)
    db_updated = datetime.fromisoformat(data["VulnerabilityDB"]["UpdatedAt"].replace("Z", "+00:00"))

    age_days = (datetime.now(timezone.utc) - db_updated).days

    assert age_days < 7, f"Trivy DB is {age_days} days old (should be < 7)"
```

**Add to CI:**

```yaml
# .github/workflows/ci.yml
- name: Test version consistency
  run: pytest tests/integration/test_version_consistency.py -v
```

---

#### Layer 5: Version Update Automation Script 🔧 TOOLING

**scripts/dev/update_versions.py:**

```python
#!/usr/bin/env python3
"""
Update tool versions across Dockerfile, install_tools.sh, and versions.yaml.

Usage:
  python3 scripts/dev/update_versions.py --tool trivy --version 0.67.2
  python3 scripts/dev/update_versions.py --check-latest  # Check for updates
  python3 scripts/dev/update_versions.py --sync          # Sync all files
"""

import argparse
import re
import yaml
import requests
from pathlib import Path

def get_latest_github_release(repo_url):
    """Fetch latest release version from GitHub."""
    # Parse owner/repo from URL
    parts = repo_url.rstrip('/').split('/')
    owner, repo = parts[-2], parts[-1]

    response = requests.get(f"https://api.github.com/repos/{owner}/{repo}/releases/latest")
    if response.ok:
        return response.json()["tag_name"].lstrip('v')
    return None

def update_dockerfile(tool, version):
    """Update tool version in Dockerfile."""
    dockerfile = Path("Dockerfile")
    content = dockerfile.read_text()

    # Find and replace version line
    pattern = rf'({tool.upper()}_VERSION=")[^"]*(")'
    replacement = rf'\g<1>{version}\g<2>'

    updated = re.sub(pattern, replacement, content, flags=re.IGNORECASE)

    if updated != content:
        dockerfile.write_text(updated)
        print(f"✅ Updated {tool} to {version} in Dockerfile")
        return True
    else:
        print(f"⚠️ No changes made to Dockerfile for {tool}")
        return False

def update_versions_yaml(tool, version):
    """Update versions.yaml registry."""
    versions_file = Path("versions.yaml")
    data = yaml.safe_load(versions_file.read_text())

    if tool in data["tools"]:
        data["tools"][tool]["version"] = version
        versions_file.write_text(yaml.dump(data, default_flow_style=False))
        print(f"✅ Updated {tool} to {version} in versions.yaml")
        return True
    return False

def check_all_updates():
    """Check for updates to all tools."""
    versions_file = Path("versions.yaml")
    data = yaml.safe_load(versions_file.read_text())

    updates_available = []

    for tool, config in data["tools"].items():
        latest = get_latest_github_release(config["release_url"])
        if latest and latest != config["version"]:
            updates_available.append({
                "tool": tool,
                "current": config["version"],
                "latest": latest,
                "critical": config.get("critical", False)
            })

    return updates_available

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--tool", help="Tool name (e.g., trivy)")
    parser.add_argument("--version", help="New version (e.g., 0.67.2)")
    parser.add_argument("--check-latest", action="store_true", help="Check for latest versions")
    parser.add_argument("--sync", action="store_true", help="Sync Dockerfile from versions.yaml")

    args = parser.parse_args()

    if args.check_latest:
        updates = check_all_updates()
        if updates:
            print("📦 Updates available:")
            for u in updates:
                flag = "🔴" if u["critical"] else "🟡"
                print(f"  {flag} {u['tool']}: {u['current']} → {u['latest']}")
        else:
            print("✅ All tools up to date")

    elif args.tool and args.version:
        update_dockerfile(args.tool, args.version)
        update_versions_yaml(args.tool, args.version)

    elif args.sync:
        # Sync all tools from versions.yaml to Dockerfile
        print("🔄 Syncing versions...")
```

**Usage:**

```bash
# Check for updates
python3 scripts/dev/update_versions.py --check-latest

# Update specific tool
python3 scripts/dev/update_versions.py --tool trivy --version 0.67.2

# Sync all versions from YAML to Dockerfile
python3 scripts/dev/update_versions.py --sync
```

---

### Recommended Workflow

**Monthly Version Review Process:**

1. **Automated Check** (every Sunday via CI)
   - CI runs version consistency check
   - Creates issues for outdated critical tools

2. **Manual Review** (first Monday of month)
   - Run: `python3 scripts/dev/update_versions.py --check-latest`
   - Review update list and release notes
   - Prioritize security-critical tools (trivy, gitleaks)

3. **Update & Test**
   - Update versions: `python3 scripts/dev/update_versions.py --tool trivy --version X.Y.Z`
   - Rebuild Docker: `docker build -t jmo-security:test .`
   - Run tests: `pytest tests/integration/test_version_consistency.py`

4. **Release**
   - Commit changes: `git commit -m "chore: update trivy to v0.67.2"`
   - CI rebuilds and publishes Docker images
   - Update CHANGELOG.md

**Emergency Security Updates:**

For critical CVE database updates (e.g., Trivy):

1. GitHub Action detects new Trivy release
2. Auto-creates issue with "security" label
3. Maintainer reviews and approves
4. Run update script: `python3 scripts/dev/update_versions.py --tool trivy --version 0.68.0`
5. Fast-track release (skip monthly cycle)

---

### Summary Table

| Strategy | Impact | Effort | Priority |
|----------|--------|--------|----------|
| Centralized versions.yaml | HIGH | LOW | ⭐⭐⭐ P0 |
| Version check CI job | HIGH | MEDIUM | ⭐⭐⭐ P0 |
| Integration tests | MEDIUM | MEDIUM | ⭐⭐ P1 |
| Update automation script | MEDIUM | LOW | ⭐⭐ P1 |
| Dependabot config | LOW | LOW | ⭐ P2 |

**Recommended Implementation:**

- **v0.5.0** (Next Release): Add versions.yaml + version check CI
- **v0.6.0**: Add integration tests + update script
- **v0.7.0**: Full automation with auto-PR creation

---

## Implementation Checklist

### Question 1: NIST Metadata
- [x] Add `nist` field to CommonFinding schema
- [ ] Update adapters to extract NIST mappings
- [ ] Add NIST display in dashboard
- [ ] Add NIST summary in SUMMARY.md
- [ ] Document NIST control mapping guide

### Question 2: Docker Optimization
- [ ] Implement multi-stage Dockerfile
- [ ] Add layer optimization
- [ ] Create Alpine variant
- [ ] Add Trivy cache persistence
- [ ] Measure size reduction
- [ ] Update documentation

### Question 3: Version Consistency
- [ ] Create versions.yaml
- [ ] Add version check CI job
- [ ] Implement integration tests
- [ ] Create update automation script
- [ ] Configure Dependabot
- [ ] Document version update process

---

**Priority for Next Release (v0.5.0):**

1. ⭐⭐⭐ **Version Consistency** - Critical (prevents Issue #4 recurrence)
2. ⭐⭐ **Docker Optimization** - Important (reduces image size by 40-50%)
3. ⭐ **NIST Metadata** - Nice-to-have (enhances compliance reporting)
