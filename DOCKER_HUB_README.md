# JMo Security Audit Tool Suite

A terminal-first, cross-platform security audit toolkit that orchestrates multiple scanners (secrets, SAST, SBOM, IaC, Dockerfile, DAST) with a unified Python CLI, normalized outputs, and an HTML dashboard.

## Quick Start

```bash
# Run full security scan on current directory
docker run --rm -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results-dir /scan/results

# Interactive wizard (easiest for beginners)
docker run --rm -it -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:latest \
  wizard

# View results
open results/summaries/dashboard.html
```

## Image Variants

| Tag | Size | Tools | Use Case |
|-----|------|-------|----------|
| `latest`, `X.Y.Z-deep` | ~1.97 GB | 28 tools | Complete scanning (deep profile, all tools) |
| `X.Y.Z-balanced` | ~1.41 GB | 18 tools | Production CI/CD pipelines (balanced profile) |
| `X.Y.Z-slim` | ~557 MB | 14 tools | Cloud-focused scanning (IaC, K8s, containers) |
| `X.Y.Z-fast` | ~502 MB | 8 tools | CI/CD gate, pre-commit hooks (fast profile) |

## Features

- 🎯 **Multi-Target Scanning**: Repos, containers, IaC, URLs, Kubernetes, GitLab
- 🔐 **28 Security Tools** (25 Docker-ready + 3 manual): Secrets (TruffleHog, Nosey Parker, Semgrep-Secrets), SAST (Semgrep, Bandit, Gosec, Horusec), SBOM (Syft, CDXgen, ScanCode), SCA (Trivy, Grype, Dependency-Check), IaC (Checkov, Checkov-CICD), Cloud (Prowler, Kubescape), DAST (ZAP, Nuclei, Akto*), Dockerfile (Hadolint), Mobile (MobSF*), Malware (YARA), System (Lynis), Runtime (Trivy-RBAC, Falco), Fuzzing (AFL++*), License (Bearer) |*Manual install required
- 📊 **Unified Reporting**: JSON, Markdown, HTML dashboard, SARIF, YAML, compliance reports
- ⚡ **Parallel Execution**: Scan multiple targets simultaneously with auto-detected CPU threads
- 🎨 **4 Docker Variants**: Fast (8 tools, 5-10 min), Balanced (18 tools, 18-25 min), Slim (14 tools, cloud-focused), Deep (25 Docker-ready tools, 40-70 min)
- 🔒 **Privacy-First Telemetry**: Anonymous usage analytics (opt-out model)
- 📈 **Real-Time Progress**: Live scan progress with ETA estimation

## What's New in v1.0.0 (December 2025)

- **Unified Profile System**: 4 profiles (fast/slim/balanced/deep) with matching Docker variants
- **SQLite Historical Storage**: Track findings over time with `jmo history` and `jmo trends`
- **Machine-Readable Diffs**: Compare scans with `jmo diff` for CI/CD integration
- **28 Security Tools**: Expanded from 11 to 28 tools across all profiles
- **Tool Management**: `jmo tools install/check/update/outdated` commands
- **Enhanced Deduplication**: 30-40% noise reduction with cross-tool similarity clustering

## Multi-Target Scanning

Scan repositories AND infrastructure in one unified workflow:

```bash
# Comprehensive security audit in one command
docker run --rm -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:latest \
  scan \
    --repo /scan/myapp \
    --image myapp:latest \
    --url https://myapp.com \
    --k8s-context prod \
    --results-dir /scan/results
```

## Documentation

- 📚 **Full Documentation**: [GitHub Repository](https://github.com/jimmy058910/jmo-security-repo)
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
      ghcr.io/jimmy058910/jmo-security:slim \
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
