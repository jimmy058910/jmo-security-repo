# JMo Security Audit Tool Suite

A terminal-first, cross-platform security audit toolkit that orchestrates 29 scanners (secrets, SAST, SBOM, SCA, IaC, Dockerfile, DAST, Kubernetes, cloud) with a unified Python CLI, normalized outputs, and an HTML dashboard.

## Quick Start

```bash
# Run a full security scan on the current directory
docker run --rm -v "$(pwd):/scan" jmogaming/jmo-security:latest \
  scan --repo /scan --results-dir /scan/results

# Interactive wizard (easiest for beginners)
docker run --rm -it -v "$(pwd):/scan" jmogaming/jmo-security:latest \
  wizard

# View results
open results/summaries/dashboard.html
```

## Image Variants

| Tag | Size | Tools | Use Case |
|-----|------|-------|----------|
| `latest`, `X.Y.Z-deep` | ~1.97 GB | 29 tools | Complete scanning (deep profile, all tools) |
| `X.Y.Z-balanced` | ~1.41 GB | 17 tools | Production CI/CD pipelines (balanced profile) |
| `X.Y.Z-slim` | ~557 MB | 13 tools | Cloud-focused scanning (IaC, K8s, containers) |
| `X.Y.Z-fast` | ~502 MB | 9 tools | CI/CD gate, pre-commit hooks (fast profile) |

Docker Hub is a replica; the primary registry is GHCR (`ghcr.io/jimmy058910/jmo-security`), and the same tags are also on ECR Public (`public.ecr.aws/m2d8u2k1/jmo-security`).

## Features

- 🎯 **Multi-Target Scanning**: Repos, containers, IaC, URLs, Kubernetes, GitLab
- 🔐 **29 Security Tools** (25 Docker-ready + 4 manual): Secrets (TruffleHog, Nosey Parker, Semgrep-Secrets), SAST (Semgrep, Bandit, Gosec, Horusec), SBOM/SCA (Syft, CDXgen, ScanCode, Trivy, Grype, Dependency-Check), IaC/Cloud (Checkov, Prowler, Kubescape), DAST (OWASP ZAP, Nuclei), plus Hadolint, ShellCheck, YARA, Lynis, OPA and Trivy-RBAC. AFL++, MobSF, Akto and Falco need a manual install.
- 📊 **Unified Reporting**: JSON, Markdown, HTML dashboard, SARIF, YAML, CSV, compliance reports
- ⚡ **Parallel Execution**: Scan multiple targets simultaneously with auto-detected CPU threads
- 🎨 **4 Docker Variants**: Fast (9 tools, 5-10 min), Balanced (17 tools, 18-25 min), Slim (13 tools, cloud-focused), Deep (29 tools, 40-70 min)
- 📈 **Real-Time Progress**: Live scan progress with ETA estimation

## What's New in v1.1.0 (September 2026)

- **Every open defect fixed before the tag, not dispositioned.** A twelve-phase pre-release fix program exercised every command path, adapter and artifact against real repositories and closed what it found before tagging.
- **Kubernetes findings now reach the report.** The kubescape adapter read a key no kubescape release emits, so every K8s scan silently yielded zero findings. Fixed and proven against real output from kubescape 3 and 4.
- **Tool installs stay isolated.** `jmo tools install <names>` and `jmo tools update` keep prowler, semgrep and checkov in their own environments instead of the interpreter's, and an update that did not change the binary now fails instead of printing `[OK]`.
- **Scanner pins current.** All 29 tools at their latest releases, including trivy 0.74 and kubescape 4.
- **The numbers in the docs are derived, not typed.** Tool counts, profile sizes and version headers are checked against the registry in CI.

Full list: [CHANGELOG.md](https://github.com/jimmy058910/jmo-security-repo/blob/main/CHANGELOG.md)

## Multi-Target Scanning

Scan repositories AND infrastructure in one unified workflow:

```bash
# Comprehensive security audit in one command
docker run --rm -v "$(pwd):/scan" jmogaming/jmo-security:latest \
  scan \
    --repo /scan/myapp \
    --image myapp:latest \
    --url https://myapp.com \
    --k8s-context prod \
    --results-dir /scan/results
```

## Documentation

- 📚 **Documentation site**: [docs.jmotools.com](https://docs.jmotools.com)
- 🚀 **Quick Start Guide**: [QUICKSTART.md](https://github.com/jimmy058910/jmo-security-repo/blob/main/QUICKSTART.md)
- 📖 **User Guide**: [USER_GUIDE.md](https://github.com/jimmy058910/jmo-security-repo/blob/main/docs/USER_GUIDE.md)
- 🐳 **Docker Guide**: [DOCKER_README.md](https://github.com/jimmy058910/jmo-security-repo/blob/main/docs/DOCKER_README.md)
- 🌐 **Project Homepage**: [jmotools.com](https://jmotools.com)

## Newsletter & Support

📬 **[Subscribe to Newsletter](https://jmotools.com/subscribe.html)** - Get security tips and updates:

- 🚀 New feature announcements
- 💡 Real-world security case studies & exclusive guides

💚 **[Support Full-Time Development](https://ko-fi.com/jmogaming)** - Help build security tools accessible to everyone

## CI/CD Integration

```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    docker run --rm -v "${{ github.workspace }}:/scan" \
      jmogaming/jmo-security:slim \
      scan --repo /scan --fail-on HIGH --results-dir /scan/results
```

## License

MIT OR Apache-2.0 - See [LICENSE](https://github.com/jimmy058910/jmo-security-repo/blob/main/LICENSE)

## Links

- **GitHub**: [jimmy058910/jmo-security-repo](https://github.com/jimmy058910/jmo-security-repo)
- **PyPI**: [jmo-security](https://pypi.org/project/jmo-security/)
- **Website**: [jmotools.com](https://jmotools.com)
- **Issues**: [GitHub Issues](https://github.com/jimmy058910/jmo-security-repo/issues)
- **Changelog**: [CHANGELOG.md](https://github.com/jimmy058910/jmo-security-repo/blob/main/CHANGELOG.md)
