# Frequently Asked Questions

Common questions about installing, running, and integrating JMo Security. For step-by-step guides see [QUICKSTART.md](../QUICKSTART.md), and for deep fixes see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## Installation

### Should I use pip or Docker?

Both are first-class; pick based on your environment:

| Use pip when... | Use Docker when... |
|-----------------|--------------------|
| You want to integrate `jmo` into scripts, Makefiles, CI containers | You want every scanner pre-installed without managing each binary yourself |
| You already have Python 3.12+ and can install extras as needed | You're scanning on a machine without Python or want isolation |
| You want the smallest install footprint | You're running one-shot audits and don't want local state |
| You're developing a custom adapter | You want consistent, reproducible results across team machines |

You can mix — use `pip` locally for development and Docker in CI. See [docs/DOCKER_README.md](DOCKER_README.md) for registry selection.

### What are the system requirements?

- **Python:** 3.12 or newer (for pip install)
- **Docker:** 24.0+ recommended (for the Docker image)
- **Disk:** ~200 MB for `pip install jmo-security`; a few GB for the Docker image
- **OS:** Linux (primary), macOS, Windows 10/11 (tested)
- **Tools (pip install only):** `jmo tools install` fetches the 12 scanners and the OPA policy engine on demand

### Is JMo Security available on Homebrew or WinGet?

Both are wired into the release pipeline via `homebrew-bump` and `winget-bump` jobs. Submissions are pending upstream review per release — check [the Releases page](https://github.com/jimmy058910/jmo-security-repo/releases) for availability. In the meantime, use `pip install jmo-security` or the Docker images.

### How do I install the scanning tools themselves?

If you installed JMo Security via pip:

```bash
jmo tools install
```

The tool installer uses isolated virtualenvs for pip-based tools (avoids conflicts with your project venv), native package managers (apt/dnf/brew/choco) when available, and binary downloads as a fallback. Run `jmo tools check` to verify.

Docker users skip this step — all scanners are pre-installed in the image.

### Do I need all 12 scanners?

No, and you rarely run them all. `jmo scan` considers every scanner, but the target's content decides which ones run: hadolint needs Dockerfiles, shellcheck needs shell scripts, gosec needs Go sources, and zap and nuclei only run on `--url` targets. To narrow the list yourself, use `--tools` (for example `jmo scan --repo . --tools trufflehog semgrep trivy`), `--skip-tools`, or a top-level `tools:` list in `jmo.yml`.

See [docs/TOOLS.md](TOOLS.md) for the full tool list and when each tool runs.

---

## Running scans

### How do I scan something that isn't a git repo?

JMo Security scans 6 target types. Examples:

```bash
# Container image
jmo scan --image nginx:latest

# IaC directory (Terraform, CloudFormation, K8s manifests)
jmo scan --iac ./infra

# Live web application (DAST)
jmo scan --url https://staging.example.com

# GitLab repository by URL
jmo scan --gitlab-url https://gitlab.com/myorg/myrepo

# Kubernetes cluster (reads current kubeconfig context)
jmo scan --k8s
```

Target flags are mutually exclusive — pick one per `jmo scan` invocation. For multi-target workflows, chain separate scans into the same results directory (or use `--repos-dir` to iterate over a parent folder of repositories).

### How long do scans take?

Runtime depends on target size, network speed (for tools fetching vulnerability databases), and which tools run. Narrow the list with `--tools` for quick feedback loops (for example `jmo scan --repo . --tools trufflehog semgrep`). See [SCAN_OPTIMIZATION.md](SCAN_OPTIMIZATION.md) for more.

### Can I skip specific tools?

Yes. List the tools you want at the top level of `jmo.yml`; anything not listed does not run:

```yaml
tools:
  - trufflehog
  - semgrep
  - trivy
per_tool:
  semgrep:
    timeout: 600
```

Or skip tools via CLI (space- or comma-separated):

```bash
jmo scan --repo . --skip-tools trivy checkov
jmo scan --repo . --skip-tools trivy,checkov   # the same
```

A name that is not a JMo tool stops the scan with exit code 2 and names it, so a typo cannot quietly skip nothing.

### Why does my scan fail with "tool not found"?

The scanner binary isn't on your `PATH`. Run `jmo tools check` to see which tools are installed, then `jmo tools install <tool>` to add missing ones. Docker users shouldn't hit this — all scanners are baked in.

### Does JMo Security send data anywhere?

No. JMo Security collects no telemetry and phones home to nothing — all scanning runs locally and no data leaves your machine. See [jmotools.com/privacy](https://jmotools.com/privacy) for the full policy.

---

## Docker specifics

### Which image should I pull?

There is one image, and it carries every scanner:

```bash
docker pull ghcr.io/jimmy058910/jmo-security:latest
```

Pin to a version tag (e.g., `:2.0.0`) in CI for reproducibility. The per-profile tags (`:fast`, `:slim`, `:balanced`, `:deep`) stopped being built with v2.0.0; old pulls of them still work but stay on v1.x.

### How do I persist scan history across Docker runs?

Mount the `.jmo/` directory:

```bash
docker run --rm \
  -v "$(pwd)/.jmo:/scan/.jmo" \
  -v "$(pwd):/scan" \
  ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan
```

The SQLite history DB (`.jmo/history.db`) persists between container runs so `jmo history`, `jmo diff`, and `jmo trends` all work.

### Why are there three Docker registries?

`ghcr.io/jimmy058910/jmo-security` is the primary. `jmogaming/jmo-security` (Docker Hub) and `public.ecr.aws/m2d8u2k1/jmo-security` (ECR Public) are replicated from GHCR on each release. Use whichever is closest to your environment or has fewer rate limits.

### Can I build a custom Docker image with just the tools I need?

Yes. Use the published image as a base, or write your own `Dockerfile` starting from `python:3.12-slim` and `pip install jmo-security`, then `jmo tools install <tool> ...` for the tools you need.

---

## CI/CD integration

### How do I wire JMo into GitHub Actions?

```yaml
jobs:
  security-scan:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/jimmy058910/jmo-security:latest
    steps:
      - uses: actions/checkout@v4
      - run: jmo ci --repo . --fail-on HIGH
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results/summaries/findings.sarif
```

See [docs/USER_GUIDE.md](USER_GUIDE.md) for GitLab, Jenkins, and CircleCI examples.

### Can I fail CI only on new findings (not existing ones)?

Yes — use `jmo diff`:

```bash
jmo scan --repo . --results-dir results-baseline
# later, on PR:
jmo scan --repo . --results-dir results-current
jmo diff results-baseline/ results-current/ --format md > diff.md
# exit code 1 if regressions detected
```

### How do I block a PR on policy violations?

OPA-based Policy-as-Code:

```bash
jmo ci --repo . --policy zero-secrets --policy owasp-top-10 --fail-on-policy-violation
```

5 built-in policies; write your own in Rego v1. See [docs/POLICY_AS_CODE.md](POLICY_AS_CODE.md).

---

## Platform-specific

### Does JMo Security work on Windows?

Yes — native Windows 10/11 is tested in CI on every release. Some tools (ZAP, Semgrep runner) work best through WSL or Docker; `jmo tools check` tells you which tools are available on your platform. See [packaging/WINDOWS_COMPATIBILITY.md](../packaging/WINDOWS_COMPATIBILITY.md).

### Does JMo Security work on Apple Silicon (arm64)?

Yes. Docker images are published as multi-arch manifests (`linux/amd64` and `linux/arm64`). pip installation works natively.

---

## Output and reports

### Where do scan results go?

Default output directory: `./results/`. Structure:

```text
results/
├── individual-repo/     # Raw per-tool JSON outputs
├── summaries/
│   ├── SUMMARY.md              # Human-readable summary
│   ├── findings.json           # Normalized CommonFinding schema
│   ├── findings.sarif          # SARIF for GitHub/GitLab code scanning
│   ├── dashboard.html          # Interactive React dashboard
│   └── simple-report.html      # Email-compatible static HTML
└── ...
```

Override with `--results-dir ./my-output`.

### What's the difference between `dashboard.html` and `simple-report.html`?

- `dashboard.html`: full React SPA with filtering, sorting, KEV-first prioritization, tooltips, dark mode. Requires a modern browser.
- `simple-report.html`: static HTML table with inline CSS. Email-client compatible (Gmail, Outlook, Apple Mail, Thunderbird). Use when you need to paste results into a compliance doc or email to non-technical stakeholders.

### How do I export to CSV or Prometheus?

CSV export is built in:

```bash
jmo report ./results --format csv --output findings.csv
```

Prometheus / Grafana export via `jmo trends` and the exporter API (see [docs/API_REFERENCE.md](API_REFERENCE.md#trend-exporters-api)).

---

## Licensing and cost

### Is JMo Security free?

Yes. Dual-licensed MIT OR Apache-2.0. Use commercially, modify, redistribute — just keep the license notice.

### Can I use JMo Security in my closed-source product?

Yes. Both MIT and Apache-2.0 allow commercial and proprietary use. If you modify scanner adapters, consider contributing back via PR — benefits everyone.

### Who maintains this?

Originally a capstone project at Institute of Data × Michigan Tech University's Cybersecurity Bootcamp (graduated October 2025). Now an independent open-source project. Maintainer: [@jimmy058910](https://github.com/jimmy058910).

---

## Support

### Where do I report bugs?

[GitHub Issues](https://github.com/jimmy058910/jmo-security-repo/issues/new) — include `jmo --version`, your OS, the command that failed, and full output.

### Where do I report security vulnerabilities?

[GitHub Security Advisories](https://github.com/jimmy058910/jmo-security-repo/security/advisories/new) — private disclosure. See [SECURITY.md](../SECURITY.md) for the full policy.

### Where do I ask usage questions?

[GitHub Discussions](https://github.com/jimmy058910/jmo-security-repo/discussions) for open-ended questions; Issues for bugs and feature requests.

---

**Last Updated:** August 2026 | **JMo Security v1.1.1**
