# Security Policy

## Reporting Security Vulnerabilities

**DO NOT** create public GitHub issues for security vulnerabilities.

Please report security issues privately via [GitHub Security Advisories](https://github.com/jimmy058910/jmo-security-repo/security/advisories/new). This creates a private report visible only to maintainers and triggers GitHub's standard CVE coordination workflow.

We aim to respond to security reports within **48 hours** and provide a fix within **7 days** for critical vulnerabilities.

---

## Understanding JMo Security's Vulnerability Profile

JMo Security is a **security audit tool suite** that bundles multiple third-party security scanners. When you see vulnerability reports for our Docker images, it's critical to understand the **source and context** of these vulnerabilities.

### Current Status (v1.1.1)

JMo Security ships one Docker image that bundles 12 scanners plus OPA, the policy engine. Its vulnerability count comes from those tools and their dependencies.

**Important:** Vulnerabilities reported in our Docker images are **NOT in our Python code** — they exist in the bundled security tools we orchestrate.

---

## Vulnerability Breakdown by Source

### 1. Ubuntu Base Image

Our Docker images use Ubuntu 22.04 LTS as the base. Kernel header vulnerabilities may appear but do not affect container security in practice since the runtime kernel is provided by the Docker host.

**Mitigation:**

- Runtime kernel security is the host's responsibility

### 2. Bundled Security Tools

Our Docker images bundle Go-based and Python-based security tools with their own dependencies. When these upstream projects have vulnerable dependencies, those vulnerabilities appear in our images.

**Mitigation:**

- We track upstream releases and update tools regularly via `versions.yaml`
- Use `jmo tools update` for native installations

### 3. OWASP ZAP (Java Dependencies)

OWASP ZAP is included in the Docker image. ZAP's Java dependencies are controlled by the ZAP project.

**Mitigation:**

- ZAP runs in **headless API mode** in our Docker image (reduces attack surface)
- ZAP runs only on `--url` targets, so a repository scan never starts it

---

## Our Python Code Security

**JMo Security's Python codebase has ZERO known vulnerabilities.**

Our Python code:

- Uses **minimal runtime dependencies**
- CI enforces **Bandit** (Python security linter) and **Ruff** (lint and format)
- Test coverage 87%+ enforced by CI (minimum 85%)

---

## Version Management

JMo Security uses a centralized version management system:

- **versions.yaml:** Central registry for every tool version
- **Automated CI checks:** Detect outdated tools
- **Update scripts:** `python scripts/dev/update_versions.py --sync`
- **Critical tool updates:** Within 7 days of upstream releases

See [VERSION_MANAGEMENT.md](docs/VERSION_MANAGEMENT.md) for details.

---

## Reducing Your Attack Surface

### Option 1: Use Native Installation

Install JMo Security via pip instead of Docker to avoid bundled tool vulnerabilities:

```bash
pip install jmo-security
jmo wizard  # Installs only the tools you need
```

**Pros:**

- No Docker image vulnerabilities
- Smaller disk footprint
- Faster startup times
- Tool versions controlled by you

**Cons:**

- Requires tool installation on host
- Platform-specific setup (Linux/macOS/WSL)

### Option 2: Custom Tool Configuration

Narrow the tool list via jmo.yml (or `--tools` / `--skip-tools` on the command line):

```yaml
# jmo.yml
tools: [trufflehog, semgrep, trivy]  # Only 3 tools
timeout: 300
```

---

## Monitoring and Response

### How We Track Vulnerabilities

1. **CI Trivy Scans:** Every release is scanned with Trivy
2. **Docker Hub Scans:** Automated vulnerability scanning
3. **GitHub Dependabot:** Tracks Python dependencies
4. **versions.yaml:** Central tool version tracking

### Vulnerability Triage Process

| Severity | Response Time | Action |
|----------|---------------|--------|
| **CRITICAL** (in our Python code) | 24 hours | Immediate patch release |
| **CRITICAL** (in bundled tools) | 7 days | Update tool version |
| **HIGH** (in our Python code) | 7 days | Patch release |
| **HIGH** (in bundled tools) | 14 days | Update in next release |
| **MEDIUM/LOW** | Next release | Batch update |

---

## Security Best Practices for Users

### 1. Run with Least Privilege

```bash
# Docker: Use read-only filesystem where possible
docker run --read-only --tmpfs /tmp ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results-dir /scan/results

# Native: Run as non-root user
jmo scan --repo ~/repos
```

### 2. Network Isolation

```bash
# Docker: Use --network=none if scanning local files only
docker run --network=none ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results-dir /scan/results
```

### 3. Regular Updates

```bash
# Docker: Pull the latest image regularly
docker pull ghcr.io/jimmy058910/jmo-security:latest

# Native: Keep pip package and tools updated
pip install --upgrade jmo-security
jmo tools update
```

---

## Frequently Asked Questions

### Q: Why don't you fix all vulnerabilities immediately?

**A:** Many vulnerabilities are in **upstream dependencies** we don't control (Go stdlib, Java libraries in ZAP). We track upstream releases and update tools as safe versions become available.

### Q: Are these vulnerabilities exploitable in my scans?

**A:** Most vulnerabilities in our images are **NOT exploitable** during normal scanning operations:

- Kernel header CVEs don't affect containers (host kernel controls security)
- Tool vulnerabilities require specific network/input conditions
- ZAP runs headless without GUI (reduces attack surface)

### Q: Should I use JMo Security if it has vulnerabilities?

**A:** **Yes, if you understand the context.** The vulnerabilities are in the security tools we bundle, not our orchestration code. Running these tools standalone would have the same vulnerabilities.

### Q: How can I verify your Python code is secure?

**A:** Inspect our CI pipeline:

1. View [.github/workflows/ci.yml](.github/workflows/ci.yml) - Bandit/Ruff checks
2. Check test coverage (87%+)
3. Review our minimal dependency footprint in `pyproject.toml`
4. Audit our source code (100% Python, no compiled binaries)

---

## Supported Versions

| Version | Supported | Status |
|---------|-----------|--------|
| 1.0.x   | Yes       | Current stable |
| < 1.0.0 | No        | Upgrade to 1.0.x |

**Docker Image:** We support the **latest patch version** of the image.

---

## Additional Resources

- **Vulnerability Tracking:** [GitHub Security Advisories](https://github.com/jimmy058910/jmo-security-repo/security/advisories)
- **Tools:** [TOOLS.md](docs/TOOLS.md)
- **Version Management:** [VERSION_MANAGEMENT.md](docs/VERSION_MANAGEMENT.md)
- **Release Notes:** [CHANGELOG.md](CHANGELOG.md)

---

## Contact

- **General Questions:** GitHub Discussions or Issues
- **Security Issues:** [GitHub Security Advisories](https://github.com/jimmy058910/jmo-security-repo/security/advisories/new)

---

**Last Updated:** August 2026 | **JMo Security v1.1.1**
