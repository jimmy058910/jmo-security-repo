# Security Policy

## Reporting Security Vulnerabilities

**DO NOT** create public GitHub issues for security vulnerabilities.

Instead, please report security issues privately via:

- **Email:** [security contact - update with your email]
- **GitHub Security Advisories:** <https://github.com/jimmy058910/jmo-security-repo/security/advisories/new>

We aim to respond to security reports within **48 hours** and provide a fix within **7 days** for critical vulnerabilities.

---

## Understanding JMo Security's Vulnerability Profile

JMo Security is a **security audit tool suite** that bundles multiple third-party security scanners. When you see vulnerability reports for our Docker images, it's critical to understand the **source and context** of these vulnerabilities.

### Current Vulnerability Status (v0.6.0)

As of October 16, 2025, our Docker images show:

- **4 CRITICAL** vulnerabilities
- **21 HIGH** vulnerabilities
- **999+ MEDIUM** vulnerabilities
- **68 LOW** vulnerabilities

**Important:** These vulnerabilities are **NOT in our Python code** — they exist in the bundled security tools we orchestrate.

---

## Vulnerability Breakdown by Source

### 1. Ubuntu Base Image (4 HIGH)

```text
Package: linux-libc-dev 5.15.0-157.167
CVEs: CVE-2022-49390, CVE-2024-35870, CVE-2024-53179, CVE-2025-38118
Status: NO FIX AVAILABLE (kernel headers from Ubuntu 22.04 LTS)
```

**Why this exists:** These are kernel header vulnerabilities in Ubuntu 22.04 LTS. The actual **runtime kernel** is provided by the Docker host, not the container. These CVEs do not affect container security in practice.

**Mitigation:**

- Use `-slim` or `-alpine` variants for minimal base image
- Plan migration to Ubuntu 24.04 LTS (ROADMAP #14)
- Runtime kernel security is the host's responsibility

### 2. Bundled Security Tools (4 CRITICAL)

Our Docker images bundle Go-based security tools that have their own dependencies:

| Tool | Vulnerability | Fix Version | Impact |
|------|---------------|-------------|--------|
| **shfmt** | Go stdlib CVE-2024-24790 | Go 1.22.4+ | Code formatter |
| **syft** | go-git CVE-2025-21613 | go-git v5.13.0+ | SBOM generator |
| **trufflehog** | go-git CVE-2025-21613 | go-git v5.13.0+ | Secrets scanner |
| **trufflehog** | golang.org/x/crypto CVE-2024-45337 | crypto v0.31.0+ | Secrets scanner |

**Why this exists:** We install the **latest released binaries** from upstream projects (TruffleHog, Syft, etc.). When these projects have vulnerable dependencies, those vulnerabilities appear in our images.

**Mitigation:**

- We track upstream releases and update tools regularly (see ROADMAP #14)
- Users can override tool versions via `jmo.yml` configuration
- Native installation (`pip install jmo-security`) avoids bundled tool vulnerabilities
- Use `-slim` variant which excludes some tools

### 3. OWASP ZAP (Java Dependencies - 2 HIGH)

```text
commons-beanutils 1.9.4 → CVE-2025-48734 (fix: 1.11.0)
delight-nashorn-sandbox 0.1.27 → CVE-2021-40660 (fix: 0.3.1)
```

**Why this exists:** OWASP ZAP is installed from upstream Docker image (`zaproxy/zap-stable`). ZAP's Java dependencies are controlled by the ZAP project, not JMo Security.

**Mitigation:**

- We track ZAP releases and update when new stable versions are available
- ZAP runs in **headless API mode** in our Docker images (reduces attack surface)
- Exclude ZAP from scans using `jmo.yml` if not needed: `tools: [trufflehog, semgrep, trivy]`

### 4. Falco and Other Runtime Tools (19 HIGH)

Falco, AFL++, and other specialized tools have their own dependency chains with occasional vulnerabilities in JWT libraries, crypto libraries, etc.

**Mitigation:**

- Use profile-based configuration to exclude tools you don't need
- `-slim` variant excludes Falco and AFL++ entirely
- We update tools weekly via automated dependency management (ROADMAP #14)

---

## Our Python Code Security

**JMo Security's Python codebase has ZERO known vulnerabilities.**

Our Python code:

- Uses **minimal runtime dependencies** (none currently in `pyproject.toml`)
- Optional dependencies (PyYAML, jsonschema) are for output formatting only
- Development dependencies are locked via `requirements-dev.txt`
- CI enforces **Bandit** (Python security linter), **Ruff**, and **Black**
- Test coverage ≥85% enforced by CI

---

## Choosing the Right Image Variant

We provide **three Docker image variants** with different tool sets and vulnerability profiles:

### 1. **Full** (`ghcr.io/jimmy058910/jmo-security:0.6.0-full`)

- **Tools:** 11 tools (trufflehog, noseyparker, semgrep, bandit, syft, trivy, checkov, hadolint, zap, falco, afl++)
- **Image Size:** ~2.5 GB
- **Vulnerabilities:** Highest count (includes all tool dependencies)
- **Use Case:** Comprehensive security audits, compliance scans, pre-release validation

### 2. **Slim** (`ghcr.io/jimmy058910/jmo-security:0.6.0-slim`)

- **Tools:** 7 tools (trufflehog, semgrep, syft, trivy, checkov, hadolint, zap)
- **Image Size:** ~1.8 GB
- **Vulnerabilities:** Medium count (excludes Falco, AFL++, noseyparker)
- **Use Case:** CI/CD pipelines, regular audits, production scans

### 3. **Alpine** (`ghcr.io/jimmy058910/jmo-security:0.6.0-alpine`)

- **Tools:** 3 tools (trufflehog, semgrep, trivy)
- **Image Size:** ~800 MB
- **Vulnerabilities:** Lowest count (minimal attack surface)
- **Use Case:** Fast scans, pre-commit checks, resource-constrained environments

**Recommendation:** Use `-alpine` for CI/CD and `-full` for comprehensive security audits.

---

## Automated Dependency Management

We are actively implementing a **5-layer version management system** to keep all tools up-to-date:

### Current Status (ROADMAP #14, Issue #46)

| Layer | Status | Description |
|-------|--------|-------------|
| **1. versions.yaml** | 🟡 Planned | Central registry for all tool versions |
| **2. Weekly CI Checker** | 🟡 Planned | Automated detection of outdated tools |
| **3. Integration Tests** | ✅ Partial | Version parity validation (Docker vs native) |
| **4. Update Script** | 🟡 Planned | One-command version updates |
| **5. Dependabot** | ✅ Active | Python dependencies (via pip-tools) |

**Timeline:**

- **v0.7.0 (Q1 2026):** Phase 1 - Foundation (`versions.yaml`, CI checker)
- **v0.8.0 (Q2 2026):** Phase 2 - Automation (update script, Dependabot)
- **v0.9.0 (Q3 2026):** Phase 3 - Advanced (auto-issue creation, smart updates)

See [ROADMAP.md](ROADMAP.md) for full details on version management.

---

## Reducing Your Attack Surface

### Option 1: Use Native Installation

Install JMo Security via pip instead of Docker to avoid bundled tool vulnerabilities:

```bash
pip install jmo-security
jmotools wizard  # Installs only the tools you need
```

**Pros:**

- No Docker image vulnerabilities
- Smaller disk footprint
- Faster startup times
- Tool versions controlled by you

**Cons:**

- Requires tool installation on host
- Platform-specific setup (Linux/macOS/WSL)

### Option 2: Use Profile-Based Scanning

Exclude tools you don't need to reduce vulnerability surface:

```yaml
# jmo.yml
default_profile: fast
profiles:
  fast:
    tools: [trufflehog, semgrep, trivy]  # Only 3 tools
    timeout: 300
```

**Impact:** `-alpine` variant + profile config → **80% reduction** in vulnerability count

### Option 3: Custom Tool Overrides

Use your own tool installations instead of bundled versions:

```yaml
# jmo.yml
per_tool:
  trivy:
    binary_path: /usr/local/bin/trivy  # Use system trivy
  trufflehog:
    binary_path: /custom/bin/trufflehog  # Use custom build
```

---

## Monitoring and Response

### How We Track Vulnerabilities

1. **CI Trivy Scans:** Every release is scanned with Trivy (see [.github/workflows/release.yml](.github/workflows/release.yml))
2. **Docker Hub Scans:** Automated vulnerability scanning on Docker Hub
3. **GitHub Dependabot:** Tracks Python dependencies and creates PRs
4. **Weekly Reviews:** Manual review of bundled tool versions (ROADMAP #14)

### Vulnerability Triage Process

| Severity | Response Time | Action |
|----------|---------------|--------|
| **CRITICAL** (in our Python code) | 24 hours | Immediate patch release |
| **CRITICAL** (in bundled tools) | 7 days | Update tool version, release v0.X.Y+1 |
| **HIGH** (in our Python code) | 7 days | Patch release |
| **HIGH** (in bundled tools) | 14 days | Update in next minor release |
| **MEDIUM/LOW** | Next minor release | Batch update |

### Suppressed Vulnerabilities

We **do not suppress** vulnerabilities via `.trivyignore`. All vulnerabilities are visible and tracked transparently.

**Exception:** Kernel header CVEs with "NO FIX AVAILABLE" may be documented as accepted risk after review.

---

## Security Best Practices for Users

### 1. **Run with Least Privilege**

```bash
# Docker: Use read-only filesystem where possible
docker run --read-only --tmpfs /tmp ghcr.io/jimmy058910/jmo-security:0.6.0-slim scan --repos-dir /repos

# Native: Run as non-root user
jmotools fast --repos-dir ~/repos
```

### 2. **Network Isolation**

```bash
# Docker: Use --network=none if scanning local files only
docker run --network=none ghcr.io/jimmy058910/jmo-security:0.6.0-alpine scan --repo /local/repo
```

### 3. **Regular Updates**

```bash
# Docker: Always pull latest patch version
docker pull ghcr.io/jimmy058910/jmo-security:0.6.0-full

# Native: Keep pip package updated
pip install --upgrade jmo-security
```

### 4. **Scan Before Production**

Always test new versions in development before deploying to CI/CD:

```bash
# Test locally first
docker run ghcr.io/jimmy058910/jmo-security:0.6.0-full --help
docker run ghcr.io/jimmy058910/jmo-security:0.6.0-full scan --repo . --profile-name fast

# Then deploy to CI
```

---

## Frequently Asked Questions

### Q: Why don't you fix all vulnerabilities immediately?

**A:** Many vulnerabilities are in **upstream dependencies** we don't control (Go stdlib in shfmt, ZAP's Java libraries). We track upstream releases and update tools as soon as safe versions are available. See ROADMAP #14 for our automated dependency management plan.

### Q: Are these vulnerabilities exploitable in my scans?

**A:** Most vulnerabilities in our images are **NOT exploitable** during normal scanning operations:

- Kernel header CVEs don't affect containers (host kernel controls security)
- Tool vulnerabilities require specific network/input conditions (we run tools in isolated processes)
- ZAP runs headless without GUI (reduces attack surface)

### Q: Should I use JMo Security if it has 1000+ vulnerabilities?

**A:** **Yes, if you understand the context.** The vulnerabilities are in the security tools we bundle, not our orchestration code. Compare to:

- Running ZAP standalone → same ZAP vulnerabilities
- Running Trivy standalone → same Trivy vulnerabilities
- **JMo Security adds no new vulnerabilities** — we just make the existing tools visible in one place

### Q: How can I verify your Python code is secure?

**A:** Inspect our CI pipeline:

1. View [.github/workflows/ci.yml](.github/workflows/ci.yml) — see Bandit/Ruff/Black checks
2. Check Codecov: <https://codecov.io/gh/jimmy058910/jmo-security-repo>
3. Review our minimal dependency footprint in `pyproject.toml`
4. Audit our source code (100% Python, no compiled binaries)

### Q: When will all vulnerabilities be fixed?

**A:** Our **Python code has zero vulnerabilities.** Bundled tool vulnerabilities will be reduced via:

- **Q1 2026 (v0.7.0):** Automated version management (50% reduction)
- **Q2 2026 (v0.8.0):** Weekly tool updates (80% reduction)
- **Q3 2026 (v0.9.0):** Ubuntu 24.04 base (kernel CVEs eliminated)

---

## Supported Versions

We provide security updates for:

| Version | Supported | Status |
|---------|-----------|--------|
| 0.6.x   | ✅ Yes    | Current stable |
| 0.5.x   | ⚠️ Limited | Patch releases for critical issues only |
| < 0.5.0 | ❌ No     | Upgrade to 0.6.x |

**Docker Images:** We support the **latest patch version** of each minor release (e.g., 0.6.0, 0.6.1, etc.).

---

## Additional Resources

- **Vulnerability Tracking:** [GitHub Security Advisories](https://github.com/jimmy058910/jmo-security-repo/security/advisories)
- **Dependency Management Roadmap:** [ROADMAP.md](ROADMAP.md)
- **GitHub Issue #46:** [Tool Version Consistency](https://github.com/jimmy058910/jmo-security-repo/issues/46)
- **GitHub Issue #12:** [Dependency Locking](https://github.com/jimmy058910/jmo-security-repo/issues/12)
- **Release Notes:** [CHANGELOG.md](CHANGELOG.md)
- **CI/CD Scans:** [.github/workflows/release.yml](.github/workflows/release.yml)

---

## Contact

- **General Questions:** GitHub Discussions or Issues
- **Security Issues:** [GitHub Security Advisories](https://github.com/jimmy058910/jmo-security-repo/security/advisories/new)
- **Commercial Support:** [Contact via project homepage]

---

**Last Updated:** October 16, 2025
**Version:** 0.6.0
