# JMo Security Audit Tool Suite

A terminal-first, cross-platform security audit toolkit that orchestrates 12 scanners (secrets, SAST, SBOM, SCA, IaC, Dockerfile, DAST, Kubernetes) with a unified Python CLI, normalized outputs, and an HTML dashboard.

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

## Image Tags

There is one image. `latest` tracks the newest release and `X.Y.Z` pins a specific one. Both carry the 12 scanners plus OPA, the policy engine.

Docker Hub is a replica; the primary registry is GHCR (`ghcr.io/jimmy058910/jmo-security`), and the same tags are also on ECR Public (`public.ecr.aws/m2d8u2k1/jmo-security`).

## Features

- 🎯 **Multi-Target Scanning**: Repos, containers, IaC, URLs, Kubernetes, GitLab
- 🔐 **12 Security Scanners**: Secrets (TruffleHog), SAST (Semgrep, Gosec), SBOM/SCA (Syft, Trivy, Grype), IaC (Checkov, Trivy), Kubernetes (Trivy), DAST (OWASP ZAP, Nuclei), plus Hadolint, ShellCheck and YARA. The target's content decides which of them run. OPA ships alongside them as the policy engine.
- 📊 **Unified Reporting**: JSON, Markdown, HTML dashboard, SARIF, YAML, CSV, compliance reports
- ⚡ **Parallel Execution**: Scan multiple targets simultaneously with auto-detected CPU threads
- 📈 **Real-Time Progress**: Live scan progress with ETA estimation

## What's New in v2.0.0

- **No more scan profiles.** `fast`, `slim`, `balanced` and `deep` are gone. `jmo scan` considers all 12 scanners and the target's content decides which run; narrow the list with `--tools` or `--skip-tools`.
- **16 tools removed**, among them kubescape, prowler, bandit (as a scanner), noseyparker and falco. Kubernetes scanning is Trivy's.
- **One image.** `latest` and version tags; the `fast`, `slim`, `balanced`, `deep` and `full` tags are no longer built.

Upgrading from v1.x: [UPGRADE.md](https://github.com/jimmy058910/jmo-security-repo/blob/main/UPGRADE.md). Full list: [CHANGELOG.md](https://github.com/jimmy058910/jmo-security-repo/blob/main/CHANGELOG.md)

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
      jmogaming/jmo-security:latest \
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
