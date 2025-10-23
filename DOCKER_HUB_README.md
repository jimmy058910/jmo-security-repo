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
| `latest`, `X.Y.Z-full` | ~2.5 GB | 14 tools | Complete scanning |
| `slim` | ~800 MB | 8 core tools | CI/CD pipelines |
| `alpine` | ~400 MB | 6 essential tools | Minimal footprint |

## Features

- 🎯 **Multi-Target Scanning**: Repos, containers, IaC, URLs, Kubernetes, GitLab (v0.6.0+)
- 🔐 **14 Security Tools**: TruffleHog, Semgrep, Trivy, Syft, Checkov, Hadolint, ZAP, Nuclei, Bandit, Nosey Parker, Falco, AFL++
- 📊 **Unified Reporting**: JSON, Markdown, HTML dashboard, SARIF, YAML, compliance reports
- ⚡ **Parallel Execution**: Scan multiple targets simultaneously
- 🎨 **3 Profiles**: Fast (5-8 min), Balanced (15-20 min), Deep (30-60 min)
- 🔒 **Privacy-First Telemetry**: Optional, anonymous usage analytics (v0.7.0+)

## Multi-Target Scanning (v0.6.0+)

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
