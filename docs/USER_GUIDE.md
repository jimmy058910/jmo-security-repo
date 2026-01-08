# JMO Security Suite — User Guide

This guide walks you through everything from a 2‑minute quick start to advanced configuration. Simple tasks are at the top; deeper features follow.

Note: The CLI is available as the console command `jmo` (via PyPI) and also as a script at `scripts/cli/jmo.py` in this repo. The examples below use the `jmo` command, but you can replace it with `python3 scripts/cli/jmo.py` if running from source.

If you're brand new, you can also use the beginner‑friendly wrapper `jmotools` described below.

## Package Manager Installation

### Homebrew (macOS/Linux)

**Easiest installation method - zero Python setup required:**

```bash
brew install jmo-security
jmo --help
```

**Benefits:**

- Zero Python setup required
- Automatic dependency management
- System-wide installation
- Auto-updates via `brew upgrade`

### WinGet (Windows 10+)

**One-command installation for Windows:**

```powershell
winget install jmo.jmo-security
jmo --help
```

**Benefits:**

- One-command install
- Bundled Python runtime
- System PATH integration
- Auto-updates via `winget upgrade`

**Complete packaging guide:** [packaging/README.md](../packaging/README.md)

## Quick start (2 minutes)

Prereqs: Linux, WSL, or macOS with Python 3.10+ recommended (3.8+ supported).

1. Install the CLI

### Option 1: Package Manager (Recommended)

```bash
# macOS/Linux
brew install jmo-security

# Windows
winget install jmo.jmo-security
```

### Option 2: Python Package

```bash
# Preferred (isolated):
pipx install "jmo-security[reporting]"

# Or using pip (user site):
pip install --user "jmo-security[reporting]"
```

The `reporting` extra bundles PyYAML and jsonschema so YAML output and schema validation work automatically. If you only need JSON/Markdown/SARIF, install the base package (`jmo-security`) instead.

1. Check tool status and install missing tools

```bash
jmo tools check --profile balanced
jmo tools install --profile balanced
```

2. Run a fast multi-repo scan + report in one step

```bash
# Scan all immediate subfolders under ~/repos with the default (balanced) profile
jmo ci --repos-dir ~/repos --fail-on HIGH --profile --human-logs

# Open the dashboard
xdg-open results/summaries/dashboard.html  # Linux
open results/summaries/dashboard.html       # macOS
```

Outputs are written under `results/` by default, with unified summaries in `results/summaries/` (JSON/MD/YAML/HTML/SARIF). SARIF is enabled by default via `jmo.yml`.

### Beginner mode: jmo wrapper (optional, simpler commands)

Prefer memorable commands that verify tools, optionally clone from a TSV, run the right profile, and open results at the end? Use `jmo`:

```bash
# Quick fast scan (auto-opens results)
jmo fast --repos-dir ~/security-testing

# Deep/full scan using the curated 'deep' profile
jmo full --repos-dir ~/security-testing --allow-missing-tools

# Clone from TSV first, then balanced scan
jmo balanced --tsv ./candidates.tsv --dest ./repos-tsv

# Bootstrap and verify curated tools (Linux/WSL/macOS)
jmo setup --check
jmo setup --auto-install
```

Makefile shortcuts are also available:

```bash
make setup             # jmo setup --check (installs package if needed)
make fast DIR=~/repos  # jmo fast --repos-dir ~/repos
make balanced DIR=~/repos
make full DIR=~/repos
```

## Everyday basics

- Scan a single repo quickly

```bash
jmo scan --repo /path/to/repo --human-logs
```

- Scan a directory of repos with a named profile

```bash
jmo scan --repos-dir ~/repos --profile-name fast --human-logs
```

- Report/aggregate from existing results only

```bash
jmo report ./results --profile --human-logs
# or equivalently
jmo report --results-dir ./results --profile --human-logs
```

- Allow missing tools (generate empty stubs instead of failing)

```bash
jmo scan --repos-dir ~/repos --allow-missing-tools
```

- Use curated helpers to prepare repos

```bash
# Clone sample repos quickly (parallel, shallow)
./scripts/core/populate_targets.sh --dest ~/security-testing --parallel 8
```

Tip: You can also run `jmo tools install` to install the security scanners for your profile, and `jmo tools check` to verify your setup.

## Tool Management

JMo Security orchestrates 28+ security scanners. For native installations (non-Docker), use the `jmo tools` command to manage these tools.

**Docker users:** Skip this section - Docker images include all tools pre-installed. Tool management is for native/pip installations only.

### Checking Tool Status

```bash
# Show profile overview (default)
jmo tools

# Check all tools for a specific profile
jmo tools check --profile balanced

# Check specific tools
jmo tools check trivy semgrep checkov

# JSON output for automation
jmo tools check --profile balanced --json
```

**Output shows:**

- Installation status (installed/missing)
- Installed vs expected versions
- Outdated indicators
- Platform-specific install hints

### Installing Tools

Tool installation is **parallel by default** (3-4x faster than sequential). Pip packages are batched, npm packages are batched, and binary downloads run concurrently.

```bash
# Interactive installation for profile (parallel, prompts for confirmation)
jmo tools install --profile balanced

# Non-interactive (CI/CD)
jmo tools install --profile balanced --yes

# Install specific tools
jmo tools install trivy semgrep checkov

# Increase parallel workers (default: 4, max: 8)
jmo tools install --profile balanced --jobs 8

# Sequential mode (for debugging)
jmo tools install --profile balanced --sequential

# Dry-run (show what would be installed)
jmo tools install --profile balanced --dry-run

# Generate install script for review
jmo tools install --profile balanced --print-script > install-tools.sh
```

**Expected installation times (parallel mode):**

| Profile | Sequential | Parallel | Speedup |
|---------|------------|----------|---------|
| fast (8 tools) | ~5-8 min | ~2-3 min | ~2.5x |
| balanced (18 tools) | ~12-18 min | ~4-6 min | ~3x |
| deep (28 tools) | ~20-30 min | ~6-10 min | ~3x |

**Installation methods (platform-specific):**

| Platform | Methods (in priority order) |
|----------|----------------------------|
| Linux | apt, pip, npm, binary download, brew |
| macOS | brew, pip, npm, binary download |
| Windows | pip, npm, binary download, manual |

**Binary downloads:** Tools like Trivy, Grype, and Syft are downloaded from GitHub releases to `~/.jmo/bin/`.

### Updating Tools

```bash
# Update all outdated tools
jmo tools update

# Update critical security tools only
jmo tools update --critical-only

# Update specific tool
jmo tools update trivy

# Non-interactive
jmo tools update --yes
```

**Critical tools** are flagged in `versions.yaml` and include tools where outdated versions may miss vulnerabilities (e.g., Trivy, TruffleHog).

### Viewing Outdated Tools

```bash
# Show all outdated tools
jmo tools outdated

# Show only critical outdated tools
jmo tools outdated --critical-only

# JSON output
jmo tools outdated --json
```

### Listing Tools and Profiles

```bash
# List all available tools
jmo tools list

# List tools in specific profile
jmo tools list --profile balanced

# List available profiles
jmo tools list --profiles

# JSON output
jmo tools list --json
```

### Uninstalling

```bash
# Remove JMo suite only (keeps tools)
jmo tools uninstall

# Remove JMo AND all installed tools
jmo tools uninstall --all

# Preview what would be removed
jmo tools uninstall --dry-run

# Skip confirmation
jmo tools uninstall --yes
```

**What gets removed with `--all`:**

- `~/.jmo/` directory (config, cache, history.db, bin/)
- pip-installed tools (semgrep, checkov, bandit, etc.)
- npm-installed tools (retire.js, etc.)
- Binary tools in `~/.jmo/bin/`
- `~/.kubescape/` directory

**What requires manual removal:**

- Homebrew-installed tools (run `brew uninstall <tool>`)
- System packages installed via apt

### Pre-Scan Tool Checks

The `jmo scan` and `jmo wizard` commands automatically check for missing tools:

**Interactive mode:**

1. Detects missing tools from requested profile
2. Prompts with options:
   - Install missing tools now
   - Continue with available tools
   - Cancel scan

**Non-interactive mode:**

- Continues with available tools (respects `--allow-missing-tools`)

**Critical update warnings:**

- Non-blocking warning at scan start if critical tools are outdated
- Suggests `jmo tools update --critical-only`

### Profile Tool Counts

| Profile | Tools | Description |
|---------|-------|-------------|
| `fast` | 8 | Pre-commit, PR validation |
| `slim` | 14 | Cloud/IaC, AWS/Azure/GCP/K8s |
| `balanced` | 18 | Production CI/CD |
| `deep` | 28 | Comprehensive audits |

**Fast profile tools:** trufflehog, semgrep, syft, trivy, checkov, hadolint, nuclei, shellcheck

**Slim profile adds:** prowler, kubescape, grype, bearer, horusec, dependency-check

**Balanced profile adds:** zap, scancode, cdxgen, gosec

**Deep profile adds:** noseyparker, semgrep-secrets, bandit, trivy-rbac, checkov-cicd, akto, yara, falco, afl++, mobsf, lynis

### Platform Support

| Platform | Installation Methods | Notes |
|----------|---------------------|-------|
| Linux | apt, pip, npm, binary, brew | apt requires sudo |
| macOS | brew, pip, npm, binary | Homebrew preferred |
| Windows | pip, npm, binary, manual | WSL recommended for full support |

## Multi-Target Scanning

Scan beyond local repositories to cover your entire infrastructure.

### Supported Target Types

JMO Security now scans 6 target types in a single unified workflow:

1. **Repositories** (existing) - Local Git repositories
2. **Container Images** (NEW) - Docker/OCI images from registries
3. **IaC Files** (NEW) - Terraform, CloudFormation, Kubernetes manifests
4. **Web URLs** (NEW) - Live web applications and APIs (DAST)
5. **GitLab Repos** (NEW) - GitLab-hosted repositories
6. **Kubernetes Clusters** (NEW) - Live K8s clusters

### Quick Examples

```bash
# Scan a container image
jmo scan --image nginx:latest --tools trivy syft

# Scan multiple images from file
jmo scan --images-file images.txt --results-dir ./image-scan

# Scan Terraform state file
jmo scan --terraform-state infrastructure.tfstate --tools checkov trivy

# Scan CloudFormation template
jmo scan --cloudformation template.yml --tools checkov trivy

# Scan Kubernetes manifest
jmo scan --k8s-manifest deployment.yaml --tools checkov trivy

# Scan live web application (DAST)
jmo scan --url https://example.com --tools zap

# Scan multiple URLs from file
jmo scan --urls-file urls.txt --tools zap

# Scan GitLab repository
jmo scan --gitlab-repo mygroup/myrepo --gitlab-token TOKEN --tools trufflehog

# Scan entire GitLab group
jmo scan --gitlab-group mygroup --gitlab-token TOKEN --tools trufflehog

# Scan Kubernetes cluster
jmo scan --k8s-context prod --k8s-namespace default --tools trivy

# Scan all namespaces in cluster
jmo scan --k8s-context prod --k8s-all-namespaces --tools trivy

# Scan multiple target types in one command
jmo scan \
  --repo ./myapp \
  --image myapp:latest \
  --terraform-state infrastructure.tfstate \
  --url https://myapp.com \
  --gitlab-repo myorg/backend \
  --k8s-context prod \
  --results-dir ./comprehensive-scan
```

### CLI Arguments Reference

#### Container Images

- `--image IMAGE`: Scan a single container image (format: `registry/image:tag`)
- `--images-file FILE`: File with one image per line (supports `#` comments)

**Example images.txt:**

```text
# Production images
nginx:latest
mysql:8.0
redis:7.2-alpine

# Custom images
myregistry.io/myapp:v1.2.3
ghcr.io/myorg/api:main
```

**Tools used:** Trivy (vulnerabilities, secrets, misconfigurations), Syft (SBOM generation)

#### IaC Files

- `--terraform-state FILE`: Terraform state file to scan
- `--cloudformation FILE`: CloudFormation template (JSON/YAML)
- `--k8s-manifest FILE`: Kubernetes manifest file

**Tools used:** Checkov (policy-as-code), Trivy (configuration scanning)

**Note:** Type detection is automatic based on flag used. All IaC files support both Checkov and Trivy scanning.

#### Web URLs (DAST)

- `--url URL`: Single web application URL to scan
- `--urls-file FILE`: File with URLs (one per line, supports `#` comments)
- `--api-spec FILE_OR_URL`: OpenAPI/Swagger spec (local file or URL)

**Example urls.txt:**

```text
# Production endpoints
https://api.example.com
https://app.example.com
https://admin.example.com/login

# Staging environment
https://staging.example.com
```

**Tools used:**

- **OWASP ZAP:** Dynamic application security testing (DAST) with spider, active scanner
- **Nuclei:** Fast vulnerability scanner with 4000+ community templates (CVEs, misconfigurations, API security)

**URL schemes supported:** `http://`, `https://`, `file://` (for local HTML files)

**Tool Selection:**

- Use `--tools zap` for comprehensive DAST with active scanning (slower, thorough)
- Use `--tools nuclei` for fast template-based scanning (CVEs, known issues)
- Use `--tools zap,nuclei` for both comprehensive + fast scanning (recommended for balanced/deep profiles)

#### GitLab Integration

- `--gitlab-url URL`: GitLab instance URL (default: `https://gitlab.com`)
- `--gitlab-token TOKEN`: GitLab access token (or use `GITLAB_TOKEN` env var)
- `--gitlab-group GROUP`: Scan all repositories in a group
- `--gitlab-repo REPO`: Single GitLab repository (format: `group/repo`)

**Tools used:** Full repository scanner (TruffleHog, Semgrep, Bandit, Trivy, Syft, Checkov, Hadolint, Noseyparker, Falco, AFL++)

**Architecture:** GitLab repos are cloned temporarily and scanned using the same repository scanner as local repos, providing comprehensive coverage instead of secrets-only scanning

**Authentication:**

```bash
# Via environment variable (recommended)
export GITLAB_TOKEN="glpat-xxxxxxxxxxxxxxxxxxxx"
jmo scan --gitlab-group mygroup

# Via CLI argument
jmo scan --gitlab-group mygroup --gitlab-token "glpat-xxxxxxxxxxxxxxxxxxxx"
```

**Permissions required:** `read_api`, `read_repository` scopes

#### Kubernetes Clusters

- `--k8s-context CONTEXT`: Kubernetes context to use (from kubeconfig)
- `--k8s-namespace NAMESPACE`: Specific namespace to scan
- `--k8s-all-namespaces`: Scan all namespaces (overrides `--k8s-namespace`)

**Tools used:** Trivy (K8s cluster vulnerabilities, misconfigurations)

**Prerequisites:**

- `kubectl` installed and configured
- Valid kubeconfig with cluster access
- Appropriate RBAC permissions (read-only sufficient)

**Examples:**

```bash
# Scan specific namespace
jmo scan --k8s-context prod --k8s-namespace default --tools trivy

# Scan all namespaces
jmo scan --k8s-context prod --k8s-all-namespaces --tools trivy

# Scan using current context
jmo scan --k8s-namespace kube-system --tools trivy
```

### Results Directory Structure

Multi-target scanning creates separate directories for each target type:

```text
results/
├── individual-repos/          # Repository scans (existing)
│   └── myapp/
│       ├── trufflehog.json
│       ├── semgrep.json
│       └── trivy.json
├── individual-images/         # Container image scans
│   └── nginx_latest/
│       ├── trivy.json
│       └── syft.json
├── individual-iac/            # IaC file scans
│   └── infrastructure/
│       ├── checkov.json
│       └── trivy.json
├── individual-web/            # Web URL scans
│   └── example_com/
│       └── zap.json
├── individual-gitlab/         # GitLab repository scans
│   └── mygroup_myrepo/
│       └── trufflehog.json
├── individual-k8s/            # Kubernetes cluster scans
│   └── prod_default/
│       └── trivy.json
└── summaries/                 # Unified aggregated reports
    ├── findings.json          # All findings from all target types
    ├── SUMMARY.md
    ├── dashboard.html
    ├── findings.sarif
    ├── COMPLIANCE_SUMMARY.md
    ├── PCI_DSS_COMPLIANCE.md
    └── attack-navigator.json
```

**Key points:**

- Each target type has its own `individual-{type}/` directory
- Target names are sanitized (special characters replaced with `_`)
- `summaries/` contains unified reports across all target types
- Findings are deduplicated by fingerprint ID across all targets

### Multi-Target CI/CD Integration

Use multi-target scanning in CI pipelines:

```yaml
# GitHub Actions example
name: Comprehensive Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Multi-Target Security Scan
        run: |
          # Scan repository code
          jmo scan --repo . --tools trufflehog semgrep trivy

          # Scan container images in docker-compose
          jmo scan \
            --image nginx:latest \
            --image redis:7.2 \
            --results-dir ./results

          # Scan IaC files
          jmo scan \
            --terraform-state terraform.tfstate \
            --k8s-manifest k8s/deployment.yaml \
            --results-dir ./results

          # Scan live staging environment
          jmo scan --url https://staging.example.com --tools zap --results-dir ./results

          # Generate unified reports
          jmo report ./results --fail-on HIGH --profile

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results/summaries/findings.sarif

      - name: Upload Dashboard
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-dashboard
          path: results/summaries/dashboard.html
```

### Advanced Multi-Target Workflows

#### Scenario 1: Complete Infrastructure Audit

Scan all infrastructure components in one command:

```bash
jmo ci \
  --repo ./application-code \
  --image myregistry.io/app:v1.0.0 \
  --terraform-state ./infra/terraform.tfstate \
  --cloudformation ./infra/cloudformation.yml \
  --url https://app.example.com \
  --k8s-context prod \
  --k8s-all-namespaces \
  --fail-on HIGH \
  --profile \
  --results-dir ./full-audit
```

#### Scenario 2: Container Registry Audit

Scan all images in your registry:

```bash
# Create images list
docker images --format "{{.Repository}}:{{.Tag}}" > registry-images.txt

# Scan all images
jmo scan --images-file registry-images.txt --tools trivy syft --results-dir ./registry-audit

# Generate report
jmo report ./registry-audit --fail-on CRITICAL
```

#### Scenario 3: Multi-Environment DAST Scanning

Scan development, staging, and production:

```bash
# Create URLs file
cat > environments.txt <<EOF
https://dev.example.com
https://staging.example.com
https://prod.example.com
EOF

# Scan all environments
jmo scan --urls-file environments.txt --tools zap --results-dir ./dast-scan
```

#### Scenario 4: GitLab Organization-Wide Audit

Scan all repositories in your GitLab organization:

```bash
export GITLAB_TOKEN="glpat-xxxxxxxxxxxxxxxxxxxx"

# Scan entire organization/group
jmo scan \
  --gitlab-url https://gitlab.company.com \
  --gitlab-group engineering \
  --tools trufflehog \
  --results-dir ./gitlab-audit \
  --threads 4
```

### Performance Tips

**1. Parallel scanning with multiple targets:**

```bash
# Separate scans in parallel (faster but separate result dirs)
jmo scan --repo ./app1 --results-dir ./results/app1 &
jmo scan --image app1:latest --results-dir ./results/app1 &
wait

# Single unified scan (slower but single result dir)
jmo scan --repo ./app1 --image app1:latest --results-dir ./results
```

**2. Use profiles for faster scanning:**

```bash
# Fast profile for quick feedback (8 tools, 300s timeout)
jmo scan --image nginx:latest --profile-name fast

# Deep profile for comprehensive audits (28 tools, 900s timeout)
jmo scan --k8s-context prod --k8s-all-namespaces --profile-name deep
```

**3. Batch processing:**

```bash
# Process batches of images
split -l 10 all-images.txt batch-
for batch in batch-*; do
  jmo scan --images-file "$batch" --results-dir "./results/$(basename $batch)"
done
```

### Tool Compatibility Matrix

| Target Type | Trivy | Syft | Checkov | ZAP | TruffleHog | Semgrep |
|-------------|-------|------|---------|-----|------------|---------|
| Repositories | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Container Images | ✓ | ✓ | - | - | - | - |
| IaC Files | ✓ | - | ✓ | - | - | - |
| Web URLs | - | - | - | ✓ | ✓ | - |
| GitLab Repos | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Kubernetes | ✓ | - | - | - | - | - |

**Note:**

- **GitLab Repos** now run full repository scanner (10/28 tools) instead of TruffleHog-only
- **Web URLs** now include Nuclei (API security scanner) in addition to ZAP
- GitLab repos also auto-discover and scan container images found in Dockerfiles, docker-compose.yml, and K8s manifests
- Tool selection is automatic based on target type. Use `--tools` to override defaults.

### Troubleshooting Multi-Target Scans

**No targets found:**

- Verify file paths exist (IaC files, image lists, URL lists)
- Check GitLab token has correct permissions
- Ensure kubectl is configured for K8s scanning

**Image scan fails:**

- Verify Docker/Podman is running for local images
- Check registry authentication for private images
- Use `docker login` before scanning private registries

**ZAP scan timeout:**

- Increase timeout: `--timeout 1200` or in `jmo.yml` per_tool override
- Reduce spider duration: `zap.flags: ["-config", "spider.maxDuration=3"]`
- Use targeted scanning with `--api-spec` instead of full crawl

**Nuclei scan issues:**

- Ensure Nuclei templates are up to date: `nuclei -update-templates`
- For private/internal apps, use: `nuclei.flags: ["-rl", "150"]` to limit request rate
- Filter by severity: `nuclei.flags: ["-severity", "critical,high"]`
- Exclude specific templates: `nuclei.flags: ["-exclude-tags", "fuzzing,dos"]`

**GitLab scan fails:**

- Verify token: `curl -H "PRIVATE-TOKEN: $GITLAB_TOKEN" https://gitlab.com/api/v4/user`
- Check group/repo name format: `group/repo` or `group/subgroup/repo`
- Ensure token has `read_api` and `read_repository` scopes

**K8s scan fails:**

- Test kubectl access: `kubectl --context prod get pods -n default`
- Check RBAC permissions: `kubectl auth can-i list pods --all-namespaces`
- Verify Trivy supports your K8s version: `trivy k8s --help`

## Output overview

All output formats use a metadata wrapper structure `{"meta": {...}, "findings": [...]}`. See [RESULTS_GUIDE.md](RESULTS_GUIDE.md) for complete specification.

Unified summaries live in `results/summaries/`:

- **findings.json** — Machine‑readable normalized findings with metadata envelope
- **findings.csv** — Spreadsheet-friendly format with metadata header
- **SUMMARY.md** — Enhanced Markdown summary (see below)
- **findings.yaml** — Optional YAML (if PyYAML available, includes metadata)
- **dashboard.html** — Interactive dashboard with dual-mode support (inline ≤1000 findings, external >1000 findings)
- **findings.sarif** — SARIF 2.1.0 output (enabled by default)
- **timings.json** — Present when `jmo report --profile` is used
- **SUPPRESSIONS.md** — Summary of filtered IDs when suppressions are applied

**Metadata Structure:**

All JSON/YAML outputs now include scan metadata:

```json
{
  "meta": {
    "output_version": "1.0.0",
    "jmo_version": "0.9.0",
    "schema_version": "1.2.0",
    "timestamp": "2025-11-04T12:34:56Z",
    "scan_id": "scan-abc123",
    "profile": "balanced",
    "tools": ["trivy", "semgrep", "trufflehog"],
    "target_count": 5,
    "finding_count": 42,
    "platform": "Linux"
  },
  "findings": [...]
}
```

Per‑repo raw tool output is under `results/individual-repos/<repo>/`.

### Enhanced Markdown Summary (SUMMARY.md)

**October 2025 Enhancement:** SUMMARY.md now provides actionable risk breakdown with remediation priorities.

**Key Features:**

- 📊 **Visual Indicators**: Emoji badges (🔴 CRITICAL/HIGH, 🟡 MEDIUM, ⚪ LOW, 🔵 INFO) for quick severity scanning
- 📁 **Top Risks by File**: Table showing top 10 files by risk with severity and most common issue
- 🔧 **By Tool**: Per-tool severity breakdown (e.g., `**trufflehog**: 32 findings (🔴 32 HIGH)`)
- ✅ **Remediation Priorities**: Top 3-5 actionable next steps prioritized by impact
- 🏷️ **By Category**: Findings grouped by type (Secrets, Vulnerabilities, IaC/Container, Code Quality) with percentages
- 📝 **Enhanced Top Rules**: Long rule IDs simplified with full name reference

**Example Output:**

```markdown
# Security Summary

Total findings: 57 | 🔴 36 HIGH | 🟡 20 MEDIUM | ⚪ 1 LOW

## Top Risks by File

| File | Findings | Severity | Top Issue |
|------|----------|----------|-----------|
| secrets-demo.json | 32 | 🔴 HIGH | generic-api-key (32×) |
| docker-compose.yml | 12 | 🟡 MEDIUM | no-new-privileges (6×) |
| Dockerfile | 2 | 🔴 HIGH | missing-user-entrypoint |

## Remediation Priorities

1. **Rotate 32 exposed secrets** (HIGH) → See findings for rotation guide
2. **Fix missing-user** (2 findings) → Review container security best practices
3. **Address 4 code security issues** → Review SAST findings

## By Category

- 🔑 Secrets: 32 findings (56% of total)
- 🔧 Code Quality: 25 findings (44% of total)
```

**Why It Matters:**

- **Executive value**: Risk breakdown and category percentages provide C-level visibility
- **Actionability**: Remediation priorities transform findings into clear next steps
- **Triage efficiency**: File breakdown shows where to focus effort first
- **Tool ROI**: Per-tool severity breakdown shows which tools contribute most value

Data model: Aggregated findings conform to a CommonFinding shape used by all reporters. See `docs/schemas/common_finding.v1.json` for the full schema. At a glance, each finding includes:

- id (stable fingerprint), ruleId, severity (CRITICAL|HIGH|MEDIUM|LOW|INFO)
- tool { name, version }, message, location { path, startLine, endLine? }
- optional: title, description, remediation, references, tags, cvss, context, raw

### EPSS/KEV Risk Prioritization

JMo Security automatically enriches CVE findings with EPSS (Exploit Prediction Scoring System) and CISA KEV (Known Exploited Vulnerabilities) data to help you prioritize remediation efforts based on real-world exploit activity.

**How It Works:**

When findings contain CVE identifiers, the system:

1. **Queries EPSS API** (FIRST.org) — Gets exploit probability (0.0-1.0) and percentile ranking
2. **Checks CISA KEV Catalog** — Identifies CVEs actively exploited in the wild
3. **Calculates Priority Score** (0-100) — Combines severity, EPSS, KEV status, and reachability

**Priority Formula:**

```text
severity_score = {CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 2, INFO: 1}
epss_multiplier = 1.0 + (epss_score × 4.0)  # Scale 0.0-1.0 → 1.0-5.0
kev_multiplier = 3.0 if is_kev else 1.0
reachability_multiplier = 1.0  # Placeholder for future enhancement

priority = (severity_score × epss_multiplier × kev_multiplier × reachability_multiplier) / 1.5
# Normalized to 0-100 scale, capped at 100
```

**Priority Thresholds:**

- **Critical (≥80)**: Immediate action required (KEV findings, high EPSS + CRITICAL severity)
- **High (60-79)**: Prioritize in next sprint (high EPSS or HIGH severity)
- **Medium (40-59)**: Address in upcoming release (moderate risk)
- **Low (<40)**: Backlog (low exploitability)

**Where You'll See It:**

1. **HTML Dashboard** — Priority column with color-coded badges, KEV indicator badges, sortable by priority
2. **SUMMARY.md** — Dedicated "Priority Analysis (EPSS/KEV)" section showing:
   - KEV findings (actively exploited CVEs)
   - High EPSS findings (>50% exploit probability in next 30 days)
   - Priority distribution (Critical/High/Medium/Low)
   - Top priority findings with score breakdown
3. **findings.json** — `priority` object with:
   - `priority`: float (0-100)
   - `epss`: float (0.0-1.0, probability of exploitation)
   - `epss_percentile`: float (0.0-1.0, ranking against all CVEs)
   - `is_kev`: boolean (true if CISA KEV)
   - `kev_due_date`: string (YYYY-MM-DD, federal agency deadline if KEV)
   - `components`: dict (severity_score, epss_multiplier, kev_multiplier, breakdown)

**Caching for Performance:**

- **EPSS**: SQLite cache with 7-day TTL (~/.jmo/cache/epss.db)
- **KEV**: JSON cache with 1-day TTL (~/.jmo/cache/kev_catalog.json)
- **Bulk API optimization**: Fetches all CVEs in single API call for speed

**Example Priority Section (SUMMARY.md):**

```markdown
## Priority Analysis (EPSS/KEV)

### ⚠️ CISA KEV: Actively Exploited (Immediate Action Required)

1. **CVE-2024-1234** (lodash@4.17.19)
   - Priority: 100/100 (CRITICAL + KEV)
   - EPSS: 0.95 (95% exploit probability, 99.9th percentile)
   - KEV Due Date: 2024-10-15
   - Location: package.json:12

### 🔥 High EPSS (>50% Exploit Probability in Next 30 Days)

1. **CVE-2024-5678** (express@4.17.1)
   - Priority: 68/100 (HIGH)
   - EPSS: 0.76 (76% exploit probability, 92nd percentile)
   - Location: package.json:15

### Priority Distribution

- Critical Priority (≥80): 1 finding
- High Priority (60-79): 1 finding
- Medium Priority (40-59): 0 findings
- Low Priority (<40): 3 findings
```

**Example HTML Dashboard Priority Column:**

| Priority | Severity | Rule ID | File | KEV |
|----------|----------|---------|------|-----|
| **100** 🔴 | CRITICAL | CVE-2024-1234 | package.json | 🚨 KEV |
| **68** 🟠 | HIGH | CVE-2024-5678 | package.json | - |
| **35** 🟡 | MEDIUM | CVE-2024-9999 | Dockerfile | - |

**Graceful Degradation:**

- If EPSS/KEV APIs unavailable, prioritization falls back to severity-only scoring
- Non-CVE findings (secrets, code quality) still receive priority scores based on severity
- No configuration required — automatic enrichment when CVEs detected

**Use Cases:**

- **Triage**: Sort dashboard by priority to focus on highest-risk findings first
- **SLA Management**: Use KEV due dates for federal compliance or internal SLAs
- **Metrics**: Track "Critical Priority" count over time as a security KPI
- **Communication**: Share KEV count with executives ("3 actively exploited CVEs found")

## Cross-Tool Deduplication

JMo Security automatically clusters duplicate findings detected by multiple tools, reducing noise by 30-40%.

### How It Works

When multiple tools detect the same underlying issue, JMo clusters them into a single "consensus finding":

**Before (3 separate findings):**

- Trivy: HIGH - SQL Injection in app.py:42
- Semgrep: HIGH - SQL injection detected in app.py:42
- Bandit: MEDIUM - Possible SQL injection in app.py:43

**After (1 consensus finding):**

- 🔍 Detected by 3 tools | HIGH CONFIDENCE
- Tools: trivy, semgrep, bandit
- SQL Injection vulnerability in query construction
- app.py:42-43

### Confidence Levels

- **HIGH:** 4+ tools agree (very likely true positive)
- **MEDIUM:** 2-3 tools agree (likely true positive)
- **LOW:** Single tool (requires validation)

### Configuration

```yaml
# jmo.yml
deduplication:
  similarity_threshold: 0.65   # Strictness (0.5-1.0, default: 0.65)
                               # Lower = more aggressive clustering (fewer duplicates shown)
                               # Higher = stricter matching (more findings shown)
```

**Environment Variable Override:**

```bash
# Override threshold for specific scans (useful in CI/CD)
export JMO_DEDUP_THRESHOLD=0.55  # More aggressive
jmo report results/

export JMO_DEDUP_THRESHOLD=0.80  # Stricter matching
jmo report results/
```

**Precedence:** Environment variable > jmo.yml > Default (0.65)

### Best Practices

1. **Trust HIGH confidence findings first** - Multiple tools agreeing is strong signal
2. **Validate MEDIUM confidence** - 2 tools may still have false positives
3. **Review LOW confidence carefully** - Single tool detections need scrutiny
4. **Check duplicate findings** - Expand duplicates in dashboard to see all detections

### How the Algorithm Works

Cross-tool deduplication uses a multi-dimensional similarity algorithm combining:

- **Location (50%):** Path + line range overlap (primary signal for same-issue detection)
- **Message (25%):** Fuzzy + token matching (e.g., "SQL injection" vs "SQL Injection vulnerability")
- **Metadata (25%):** CWE/CVE/Rule ID matching + rule equivalence mapping

Findings with similarity above the configured threshold (default: 65%) are clustered together. The highest-severity finding becomes the representative, and others are attached as duplicates in `context.duplicates`.

**Algorithm Selection:**

- **<500 findings:** Greedy algorithm (O(n×k), simpler overhead)
- **≥500 findings:** LSH algorithm (O(n log n), uses locality-sensitive hashing for scalability)

**Example Consensus Finding:**

```json
{
  "id": "cluster-abc123",
  "severity": "HIGH",
  "message": "SQL Injection vulnerability in query construction",
  "detected_by": [
    {"name": "trivy", "version": "0.50.0"},
    {"name": "semgrep", "version": "1.60.0"},
    {"name": "bandit", "version": "1.7.0"}
  ],
  "confidence": {
    "level": "HIGH",
    "tool_count": 3,
    "avg_similarity": 0.87
  },
  "context": {
    "duplicates": [
      {
        "id": "fp2",
        "tool": {"name": "semgrep"},
        "similarity_score": 0.90
      },
      {
        "id": "fp3",
        "tool": {"name": "bandit"},
        "similarity_score": 0.85
      }
    ]
  }
}
```

### Disabling Clustering

If you prefer to see all findings from all tools separately:

```yaml
# jmo.yml
deduplication:
  cross_tool_clustering: false
```

This reverts to Phase 1 deduplication only (same tool, same location).

### Performance Impact

- **Time:** <2 seconds for 1000 findings, <10 seconds for 10000 findings
- **Scalability:** LSH algorithm enables O(n log n) clustering for large scans
- **Reduction:** 30-40% fewer reported findings (noise elimination)
- **Accuracy:** ≥85% clustering accuracy (validated on 200+ finding sample)

## Configuration (jmo.yml)

`jmo.yml` controls what runs and how results are emitted. Top‑level fields supported by the CLI include:

- tools: [trufflehog, noseyparker, semgrep, syft, trivy, checkov, hadolint, zap, nuclei, falco, afl++, bandit]
  - Note: Added Nuclei for API security scanning (CVEs, misconfigurations, 4000+ templates)
  - Note: Removed deprecated tools (gitleaks, tfsec, osv-scanner). Added DAST (zap), runtime security (falco), and fuzzing (afl++)
- outputs: [json, md, yaml, html, simple-html, sarif, csv]
- fail_on: "CRITICAL|HIGH|MEDIUM|LOW|INFO" (empty means do not gate)
- threads: integer worker hint (auto if unset)
- include / exclude: repo name glob filters (applied when using --repos-dir or --targets)
- timeout: default per‑tool timeout seconds
- log_level: DEBUG|INFO|WARN|ERROR (defaults to INFO)
- retries: global retry count for flaky tool invocations (0 by default)
- default_profile: name of the profile to use when --profile-name is not provided
- profiles: named profile blocks
- per_tool: global per‑tool overrides (merged with per‑profile overrides)

Example:

```yaml
tools: [trufflehog, semgrep, syft, trivy, checkov, hadolint, zap, nuclei]
outputs: [json, md, yaml, html, simple-html, sarif, csv]
fail_on: ""
default_profile: balanced
threads: 4
retries: 0

profiles:
  fast:
    tools: [trufflehog, semgrep, trivy]
    threads: 8
    timeout: 300
    include: ["*"]
    exclude: ["big-monorepo*"]
    per_tool:
      semgrep:
        flags: ["--exclude", "node_modules", "--exclude", ".git"]
  balanced:
    tools: [trufflehog, semgrep, syft, trivy, checkov, hadolint, zap, nuclei]
    threads: 4
    timeout: 600
    per_tool:
      trivy:
        flags: ["--no-progress"]
      zap:
        flags: ["-config", "api.disablekey=true", "-config", "spider.maxDuration=5"]
  deep:
    tools: [trufflehog, noseyparker, semgrep, bandit, syft, trivy, checkov, hadolint, zap, nuclei, falco, afl++]
    threads: 2
    timeout: 900
    retries: 1
    per_tool:
      zap:
        flags: ["-config", "api.disablekey=true", "-config", "spider.maxDuration=10"]
      falco:
        timeout: 600
      afl++:
        timeout: 1800
        flags: ["-m", "none"]
```

Use a profile at runtime:

```bash
jmo scan --repos-dir ~/repos --profile-name fast
```

Notes and precedence:

- Severity order is CRITICAL > HIGH > MEDIUM > LOW > INFO. Thresholds gate at and above the chosen level.
- Threads/timeout/tool lists are merged from config + profile; CLI flags override config/profile where provided.
- Per‑tool overrides are merged with root config; values set in a profile win over root.

### Telemetry Configuration

JMo Security can collect anonymous usage statistics to help prioritize features and improve the tool. Telemetry is **disabled by default** (opt-in only) and fully respects your privacy with a privacy-first, opt-in design.

#### What We Collect (Anonymous Only)

✅ **What we collect:**

- Tool usage (which tools ran)
- Scan duration (bucketed: <5min, 5-15min, etc.)
- Execution mode (CLI/Docker/Wizard)
- Platform (Linux/macOS/Windows)
- Profile selected (fast/slim/balanced/deep)
- Target count (bucketed: 1, 2-5, 6-10, etc.)
- CI detection (running in CI/CD environment)

❌ **What we DON'T collect:**

- Repository names or paths
- Finding details or secrets
- IP addresses or user info
- File contents or code snippets
- Tool output or vulnerability details

#### Privacy Guarantees

- **Anonymous UUID:** Randomly generated, stored locally in `~/.jmo-security/telemetry-id`
- **No PII:** No personally identifiable information ever collected
- **Privacy Bucketing:** All metrics bucketed (duration, findings count, target count)
- **Secure Storage:** Events sent to private GitHub Gist (not public database)
- **GDPR/CCPA Compliant:** Opt-in only, anonymous data, right to be forgotten

#### Enabling Telemetry

##### Option 1: Wizard Prompt (Interactive)

The wizard will ask on first run:

```bash
jmo wizard

# Prompted:
# 📊 Help Improve JMo Security
# Enable anonymous telemetry? [y/N]:
```

##### Option 2: Manual Configuration

Add to `jmo.yml`:

```yaml
telemetry:
  enabled: true  # Default: false (opt-in only)
```

##### Option 3: Environment Variable (CI/CD)

Disable for CI/CD environments:

```bash
export JMO_TELEMETRY_DISABLE=1  # Force disable
jmo scan --repo ./myapp
```

#### What Events Are Sent

1. **scan.started** — When scan begins (profile, tools, target types, CI detection)
2. **scan.completed** — When scan finishes (duration, tools succeeded/failed)
3. **tool.failed** — When individual tool fails (tool name, error type)
4. **wizard.completed** — When wizard finishes (profile selected, execution mode)
5. **report.generated** — When report completes (output formats, findings count)

#### Telemetry Backend

- **MVP:** GitHub Gist (private, append-only JSONL)
- **Future:** Cloudflare Workers for scale (when >10k users)

#### Transparency Reports

Aggregated, anonymized statistics published quarterly at:

- [jmotools.com/telemetry](https://jmotools.com/telemetry) (future)
- GitHub Discussions (community feedback)

#### Disabling Telemetry

##### Option 1: Config File

```yaml
telemetry:
  enabled: false  # Explicitly disable
```

##### Option 2: Environment Variable

```bash
export JMO_TELEMETRY_DISABLE=1
```

##### Option 3: Delete Anonymous ID

```bash
rm ~/.jmo-security/telemetry-id
```

#### Privacy Policy

Full privacy policy and data handling details:

- [docs/TELEMETRY.md](TELEMETRY.md) — Complete telemetry documentation
- [jmotools.com/privacy](https://jmotools.com/privacy) — Privacy policy (future)

**Questions or concerns?** Open an issue at [github.com/jimmy058910/jmo-security-repo/issues](https://github.com/jimmy058910/jmo-security-repo/issues)

## Plugin System

JMo Security uses a plugin-based architecture for all 28 security tool adapters, enabling hot-reload during development and community-contributed integrations.

**Key Benefits:**

- **Hot-Reload** - Edit adapter code without reinstalling JMo
- **Fast Development** - 4 hours → 1 hour per adapter (75% reduction)
- **Low-Risk Testing** - Test new tools in `~/.jmo/adapters/` without modifying core

**Quick Commands:**

```bash
# List all loaded plugins
jmo adapters list

# Validate custom adapter
jmo adapters validate ~/.jmo/adapters/custom_tool_adapter.py
```

**Plugin Search Paths (priority order):**

1. `~/.jmo/adapters/` - User plugins (highest priority)
2. `scripts/core/adapters/` - Built-in plugins

**Complete Guide:** [CONTRIBUTING.md — Adding Tool Adapters](../CONTRIBUTING.md#adding-tool-adapters)

## Schedule Management

### Automate recurring security scans with Kubernetes-inspired scheduling

JMo Security provides a comprehensive schedule management system for automated, recurring scans with:

- **Cron-based scheduling** with full cron syntax support
- **Local persistence** in `~/.jmo/schedules.json` with secure permissions (0o600)
- **Multiple backends**: GitLab CI, GitHub Actions, local cron
- **Slack notifications**: Success/failure alerts to team channels
- **Kubernetes-inspired API**: Familiar metadata/spec/status patterns for DevOps teams

### Quick Start

```python
from scripts.core.schedule_manager import (
    ScheduleManager, ScanSchedule, ScheduleMetadata,
    ScheduleSpec, BackendConfig, JobTemplateSpec
)

# Initialize manager
manager = ScheduleManager()

# Create weekly scan schedule
schedule = ScanSchedule(
    metadata=ScheduleMetadata(
        name="weekly-prod-scan",
        labels={"team": "security", "environment": "production"}
    ),
    spec=ScheduleSpec(
        schedule="0 2 * * 1",  # Every Monday at 2 AM UTC
        timezone="UTC",
        backend=BackendConfig(type="gitlab-ci"),
        jobTemplate=JobTemplateSpec(
            profile="balanced",
            targets={"repos_dir": "/repos"},
            results={"dir": "/results"},
            options={"fail_on": "HIGH"},
            notifications={
                "enabled": True,
                "channels": [
                    {
                        "type": "slack",
                        "url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
                    }
                ]
            }
        )
    )
)

# Save schedule
manager.create(schedule)
print(f"✅ Created schedule: {schedule.metadata.name}")
print(f"📅 Next run: {schedule.status.nextScheduleTime}")
```

### Schedule CLI Commands

**Status:** Implemented for GitLab CI backend. GitHub Actions and local cron support in active development.

**Available commands:**

```bash
# Create schedule
jmo schedule create nightly-deep \
  --cron "0 2 * * *" \
  --profile deep \
  --repos-dir ~/repos \
  --backend gitlab-ci \
  --description "Nightly deep security audit"

# List all schedules
jmo schedule list

# Get specific schedule
jmo schedule get nightly-deep

# Update schedule
jmo schedule update nightly-deep --profile balanced

# Delete schedule
jmo schedule delete nightly-deep --force

# Export to GitLab CI
jmo schedule export nightly-deep --backend gitlab-ci > .gitlab-ci.yml

# Suspend/resume (coming soon)
jmo schedule suspend nightly-deep
jmo schedule resume nightly-deep
```

**Supported backends:**

| Backend | Status | Platform |
|---------|--------|----------|
| **gitlab-ci** | ✅ Complete | GitLab CI/CD |
| **github-actions** | 🚧 In development | GitHub Actions |
| **local-cron** | 🚧 Partial | Linux/macOS cron |

**Complete guide:** [docs/SCHEDULE_GUIDE.md](SCHEDULE_GUIDE.md)

**Python API:** For programmatic access, use the ScheduleManager API (see below)

### Managing Schedules

**List all schedules:**

```python
manager = ScheduleManager()

# List all
schedules = manager.list()
for s in schedules:
    print(f"{s.metadata.name}: {s.spec.schedule} (next: {s.status.nextScheduleTime})")

# Filter by labels
prod_schedules = manager.list(labels={"environment": "production"})
```

**Update existing schedule:**

```python
schedule = manager.get("weekly-scan")
schedule.spec.schedule = "0 3 * * *"  # Change to 3 AM
schedule.spec.jobTemplate.profile = "deep"  # Use deep profile
manager.update(schedule)
```

**Delete schedule:**

```python
success = manager.delete("weekly-scan")
```

### GitLab CI Integration

**Generate GitLab CI YAML:**

```python
from scripts.core.workflow_generators.gitlab_ci import GitLabCIGenerator

generator = GitLabCIGenerator()
schedule = manager.get("weekly-scan")
yaml_content = generator.generate(schedule)

# Write to .gitlab-ci.yml
with open(".gitlab-ci.yml", "w") as f:
    f.write(yaml_content)
```

**Generated YAML includes:**

- Profile-based scan job (fast/slim/balanced/deep)
- Multi-target support (all 6 target types)
- Slack success/failure notifications
- SARIF upload for GitLab security dashboard
- Artifact persistence

**GitLab schedule setup:**

1. Navigate to **CI/CD > Schedules** in GitLab
2. Create new schedule with cron syntax from `schedule.spec.schedule`
3. Set timezone to `UTC`
4. GitLab will run `.gitlab-ci.yml` on schedule

### Slack Notifications

**Setup webhook:**

1. Go to [Slack API: Incoming Webhooks](https://api.slack.com/messaging/webhooks)
2. Create app and enable Incoming Webhooks
3. Add webhook to workspace channel (e.g., `#security-alerts`)
4. Copy webhook URL: `https://hooks.slack.com/services/T00/B00/XXX`

**Configure in schedule:**

```python
notifications={
    "enabled": True,
    "channels": [
        {
            "type": "slack",
            "url": "https://hooks.slack.com/services/T00/B00/XXX"
        }
    ]
}
```

**Best practice:** Use environment variables or CI/CD secrets, never hardcode webhook URLs

**Multiple channels:**

```python
notifications={
    "enabled": True,
    "channels": [
        {"type": "slack", "url": os.environ["SLACK_SECURITY"]},  # #security
        {"type": "slack", "url": os.environ["SLACK_DEVOPS"]}     # #devops
    ]
}
```

### Cron Syntax Reference

Standard 5-field cron format:

```text
┌─ minute (0-59)
│ ┌─ hour (0-23)
│ │ ┌─ day of month (1-31)
│ │ │ ┌─ month (1-12)
│ │ │ │ ┌─ day of week (0-7, Sunday=0 or 7)
│ │ │ │ │
* * * * *
```

**Common patterns:**

```python
"0 2 * * *"      # Every day at 2 AM UTC
"0 2 * * 1"      # Every Monday at 2 AM UTC
"0 */6 * * *"    # Every 6 hours
"0 9 * * 1-5"    # Every weekday at 9 AM UTC
"0 0 1 * *"      # First day of month at midnight
"*/15 * * * *"   # Every 15 minutes (testing)
```

### Advanced Configuration

**Concurrency policies:**

```python
spec=ScheduleSpec(
    schedule="0 2 * * *",
    concurrencyPolicy="Forbid"  # Skip if previous still running
    # Options: "Forbid" (default), "Allow", "Replace"
)
```

**History limits:**

```python
spec=ScheduleSpec(
    schedule="0 2 * * *",
    successfulJobsHistoryLimit=30,  # Keep 30 successful runs
    failedJobsHistoryLimit=10       # Keep 10 failed runs
)
```

**Suspend schedule temporarily:**

```python
schedule = manager.get("weekly-scan")
schedule.spec.suspend = True  # Pause
manager.update(schedule)

schedule.spec.suspend = False  # Resume
manager.update(schedule)
```

### Complete Documentation

For comprehensive schedule management documentation, see:

- **[docs/SCHEDULE_GUIDE.md](SCHEDULE_GUIDE.md)** — Complete guide with examples
- **[docs/examples/slack-notifications.md](examples/slack-notifications.md)** — Slack integration patterns
- **[docs/examples/.gitlab-ci.yml](examples/.gitlab-ci.yml)** — GitLab CI examples

## Key CLI commands and flags

Subcommands: scan, report, ci, setup, wizard, history, trends, diff, schedule, adapters

### `jmo setup`

**Interactive setup wizard for first-time JMo Security configuration.**

```bash
jmo setup
```

**Description:**

Interactive setup wizard for first-time JMo Security configuration. Guides users through:

- Tool installation verification
- Configuration file creation (jmo.yml)
- Database initialization (.jmo/history.db)
- Environment validation

**Use Cases:**

- First-time installation
- Resetting configuration to defaults
- Verifying tool availability

**Example:**

```bash
# Run interactive setup
jmo setup

# Setup automatically:
# 1. Checks for installed security tools
# 2. Creates jmo.yml with recommended profile
# 3. Initializes SQLite history database
# 4. Validates Python dependencies
```

**See Also:**

- `jmo wizard` - Full guided scanning workflow
- Installation - Manual installation steps

### Common flags

- --config jmo.yml: choose a config file (default: jmo.yml)
- --profile-name NAME: apply a named profile from config
- --threads N: set workers (scan/report)
- --timeout SECS: default per‑tool timeout (scan)
- --tools ...: override tool list (scan/ci)
- --fail-on SEVERITY: gate the exit code during report/ci
- --human-logs: color, human‑friendly logs on stderr (default logs are JSON)
- --allow-missing-tools: write empty JSON stubs if a tool is not found (scan/ci)
- --profile (report/ci): write timings.json with summary and per‑job timings

Notes on exit codes:

- Some tools intentionally return non‑zero to signal "findings." The CLI treats these as success codes internally (trufflehog/trivy/checkov: 0/1; semgrep: 0/1/2; zap: 0/1/2) to avoid false failures.
- The overall exit code of report/ci can be gated by --fail-on or fail_on in config.

Graceful cancel:

- During scans, Ctrl‑C (SIGINT) will request a graceful stop after in‑flight tasks finish.

Environment variables:

- JMO_THREADS: when set, influences worker selection during scan; report also seeds this internally based on `--threads` or config to optimize aggregation.
- JMO_PROFILE: when set to 1, aggregation collects timing metadata; `--profile` toggles this automatically for report/ci and writes `timings.json`.

## Per‑tool overrides and retries

You can supply global `per_tool` overrides at the root and/or inside a profile; profile values win and are merged. Supported keys are free‑form; commonly used keys include `flags` (list of strings) and `timeout` (int).

Example:

```yaml
per_tool:
  trivy:
    flags: ["--ignore-unfixed"]
    timeout: 1200
profiles:
  balanced:
    per_tool:
      semgrep:
        flags: ["--exclude", "node_modules", "--exclude", ".git"]
```

Retries:

- Set `retries: N` at the root or inside a profile to automatically retry failing tool commands up to N times.
- Human logs will show attempts when > 1, e.g. `attempts={'semgrep': 2}`.

Threading and performance:

- Scan workers: precedence is CLI/profile threads > JMO_THREADS env > config default > auto.
- Report workers: set via `--threads` (preferred) or config; the aggregator will also suggest `recommended_threads` in `timings.json` based on CPU count.

## Suppressions

You can suppress specific finding IDs during report/ci. The reporter looks for `jmo.suppress.yml` first in `results/` and then in the current working directory.

File format:

```yaml
suppressions:

  - id: abcdef1234567890
    reason: false positive (hashing rule)
    expires: 2025-12-31   # optional ISO date; omit to never expire

  - id: 9999deadbeef
    reason: accepted risk for demo
```

Behavior:

- Active suppressions remove matching findings from outputs.
- A suppression summary (`SUPPRESSIONS.md`) is written alongside summaries listing the filtered IDs.
- The tool automatically detects which key (`suppressions` or `suppress`) is present in your config.

Search order for the suppression file is: `<results_dir>/jmo.suppress.yml` first, then `./jmo.suppress.yml` in the current working directory.

## SARIF and HTML dashboard

### SARIF 2.1.0 Output (Enriched)

- SARIF emission is enabled by default in this repo (`outputs: [json, md, yaml, html, simple-html, sarif, csv]`). If you remove `sarif` from outputs, SARIF won't be written.
- **Enhanced in Phase 1:** SARIF output now includes:
  - **Code snippets** in region context for better IDE integration
  - **CWE/OWASP/CVE taxonomy references** for security categorization
  - **CVSS scores and metadata** for vulnerability prioritization
  - **Richer rule descriptions** and fix suggestions
  - **Improved GitHub/GitLab code scanning integration**

### HTML Dashboard v2 (Enhanced UX)

The HTML dashboard (`dashboard.html`) is a fully self-contained, zero-dependency interactive interface for exploring findings. **October 2025 v2 redesign** transforms it into an actionable remediation platform.

#### Core Features

**Traditional Features:**

- Client-side sorting by any column (severity, tool, file, line, rule)
- Tool filtering dropdown with finding counts
- CSV/JSON export for external analysis
- Persisted filters/sort preferences (survives page reloads)
- Deep-linkable URLs for sharing specific filter/sort states
- Profiling panel (when `--profile` flag used during report/ci)

**New in v2 (October 2025):**

#### 1. Expandable Rows with Code Context

Click any finding row to expand and view:

- **Syntax-highlighted code snippet** (2-5 lines of context)
- **Line numbers** matching actual file locations
- **Highlighted match line** for quick visual identification
- **Language-aware coloring** (Dockerfile, Python, JavaScript, YAML, etc.)

**Why:** Eliminates IDE context-switching, enables triage directly from dashboard.

#### 2. Suggested Fixes Display

For tools that provide autofix suggestions (Semgrep):

- **"Suggested Fix" column** with collapsible content
- **One-click "Copy Fix" button** for instant remediation
- **Fix diffs** shown in code block format with proper escaping
- **Remediation steps** displayed as actionable checklist

**Example:** Semgrep's `missing-user-entrypoint` rule shows exact code to add (`USER non-root`) with copy button.

#### 3. Secrets Context Enhancement

For secrets detected by Gitleaks/TruffleHog:

- **Full secret value** displayed (NOT redacted) for rotation workflows
- **Entropy score** for randomness assessment
- **Git metadata**: `🔑 <secret> (entropy: 4.25) in commit <sha> by <author>`
- **"View in GitHub" button** linking directly to commit
- **Step-by-step rotation guide** in remediation section

**Why:** Streamlines secret rotation, provides full provenance for audit trails.

#### 4. Grouping Modes

**Group by selector:** None | File | Rule | Tool | Severity

- **Collapsible groups** with finding counts and severity indicators
- **Visual progress bars** showing severity distribution within groups
- **Nested findings** under each group with full expand/collapse
- **Example:**

  ```text
  ▼ /home/jimmy058910/jmo-security-repo/Dockerfile (3 findings) ████████████ HIGH
    ├─ missing-user-entrypoint (line 145) HIGH
    ├─ missing-user (line 148) HIGH
    └─ apt-get-no-fix-version (line 89) MEDIUM
  ```

**Why:** Reduces cognitive load, enables file-centric or rule-centric workflows.

#### 5. Enhanced Filters

**New filter types:**

- **CWE Filter**: Multi-select CWE identifiers with autocomplete (e.g., CWE-269, CWE-78)
- **OWASP Filter**: Filter by OWASP Top 10 categories (e.g., A04:2021, A03:2021)
- **Path Patterns**: Regex/glob filtering (e.g., `**/test/**`, `*.py`, `^src/`)
- **Multi-select Severity**: Checkboxes for CRITICAL + HIGH + MEDIUM (replaces single-select)
- **Tool Filter**: Enhanced with finding counts per tool

**Traditional filters still available:**

- Tool dropdown (trufflehog, semgrep, trivy, zap, etc.)
- Severity single-select (backward compatible)
- Search box (free text across all fields)

#### 6. Triage Workflow

**Bulk triage capabilities:**

- **Checkbox column** for multi-select
- **Bulk actions dropdown**: "Mark as: Fixed | False Positive | Accepted Risk | Needs Review"
- **Triage state persistence**: Saved in `localStorage` (survives page reloads)
- **Status badges**:
  - 🟢 Fixed
  - ❌ False Positive
  - ⚠️ Accepted Risk
  - 🔵 Needs Review
- **Export triage decisions** to `results/summaries/triage.json` for CI integration

**Workflow:**

1. Filter findings (e.g., "Show all HIGH in `src/`")
2. Select findings via checkboxes
3. Bulk mark as "False Positive" with reason
4. Export `triage.json` for CI gating

**Future:** CLI command `jmo triage` to manage triage state from command line.

#### 7. Risk Metadata Display

**CWE/OWASP badges:**

- **Tooltips** on badges showing full CWE/OWASP descriptions
- **Confidence indicators** (HIGH/MEDIUM/LOW) with color coding
- **Hover over severity badges** to see CWE identifiers and CVSS scores
- **Filterable by compliance frameworks** (OWASP, CWE, PCI-DSS)

**Example:** A Trivy finding shows:

```text
Severity: HIGH (CWE-269, OWASP A04:2021)
Confidence: MEDIUM
CVSS: 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
```

#### Security Enhancements

- **XSS vulnerability patched** (Phase 1): Comprehensive HTML escaping covering all dangerous characters (`&`, `<`, `>`, `"`, `'`)
- **Safe rendering** of user-controlled data (file paths, messages, code snippets)
- **No external dependencies**: Fully self-contained HTML file (works offline)

#### Dashboard Architecture

**All extended fields are optional**: Dashboard gracefully handles missing fields with progressive enhancement.

#### Dual-Mode Architecture

The HTML dashboard automatically switches between two rendering modes based on dataset size to optimize performance and prevent browser freezing.

**Inline Mode (≤1000 findings):**

- **Behavior**: Findings embedded directly in HTML file
- **File**: Single self-contained `dashboard.html` (~800 KB for 1000 findings)
- **Loading**: Instant (<100ms)
- **Benefits**: Portable (single file), works offline, easy to share
- **Best For**: Small to medium scans, sharing via email/Slack

**External Mode (>1000 findings):**

- **Behavior**: Findings loaded asynchronously from `findings.json`
- **Files**: `dashboard.html` (63 KB) + `findings.json` (variable size)
- **Loading**: Async fetch with professional loading UI (spinner, progress)
- **Benefits**: Fast page load, supports massive datasets (10,000+ findings)
- **Best For**: Large scans, enterprise environments, CI/CD pipelines

**Automatic Threshold:**

- **Switch Point**: 1000 findings (`INLINE_THRESHOLD = 1000`)
- **No Configuration Needed**: Automatically activates based on finding count
- **Performance Impact**: 95% reduction in load time for >1000 findings (30-60s → <2s)

**Loading UI (External Mode):**

```text
┌─────────────────────────────────────┐
│                                     │
│         [Loading Spinner]           │
│   Loading Security Findings...      │
│   Please wait while we fetch data   │
│                                     │
└─────────────────────────────────────┘
```

**Error Handling:**

If `findings.json` fails to load (network error, missing file):

```text
┌─────────────────────────────────────┐
│    ⚠️ Loading Failed                 │
│                                     │
│  Could not load findings.json       │
│  Make sure findings.json is in      │
│  the same directory as this HTML.   │
└─────────────────────────────────────┘
```

**File Size Comparison (1500 findings):**

| Mode | dashboard.html | findings.json | Total | Load Time |
|------|----------------|---------------|-------|-----------|
| Inline (≤1000 findings) | ~84 KB (100 findings) | N/A | ~84 KB | <100ms |
| External (>1000 findings) | 63 KB | 448 KB | 511 KB | <2s |

**Performance Benefits:** External mode prevents browser freeze and supports massive datasets (10,000+ findings) with professional loading UX.

### CSV Reporter

Export findings to spreadsheet-friendly CSV format for Excel, Google Sheets, or data analysis workflows.

**Output File:** `results/summaries/findings.csv`

**Features:**

- **Metadata Header**: Scan information in comment rows (lines starting with `#`)
- **Standard CSV Format**: RFC 4180 compliant
- **UTF-8 Encoding**: Full Unicode support for international characters
- **Column Headers**: Priority, KEV, EPSS, Severity, RuleID, Path, Line, Message, Tool, Detected By, Triaged
- **Triage Status**: Integrates with `jmo.suppress.yml` to show which findings have been reviewed

**Columns Explained:**

| Column | Description |
|--------|-------------|
| `priority` | Composite priority score (0-10) |
| `kev` | YES/NO - Is this a Known Exploited Vulnerability? |
| `epss` | EPSS exploitation probability percentage |
| `severity` | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| `ruleId` | Rule or CVE identifier |
| `path` | File path |
| `line` | Line number |
| `message` | Finding description |
| `tool` | Primary detecting tool |
| `detected_by` | All tools that detected this finding (for consensus findings) |
| `triaged` | YES/NO - Has an active suppression rule in `jmo.suppress.yml` |

**Example Output:**

```csv
priority,kev,epss,severity,ruleId,path,line,message,tool,detected_by,triaged
8.5,NO,,CRITICAL,github,config.py,15,GitHub Personal Access Token detected,trufflehog,trufflehog,NO
7.2,YES,45.32%,HIGH,CVE-2024-1234,package.json,0,Vulnerability in lodash,trivy,trivy,YES
3.5,NO,0.12%,MEDIUM,python.lang.security.audit.dangerous-code-exec,app.py,42,Use of exec() detected,semgrep,"semgrep, bandit",NO
```

**Triage Status Integration:**

The `triaged` column shows "YES" when a finding has an active suppression rule in `jmo.suppress.yml`:

```yaml
# jmo.suppress.yml
suppressions:
  - id: "trivy|CVE-2024-1234|package.json|0|abc123"
    reason: "Accepted risk - not exploitable in our context"
    expires: 2025-12-31
```

This enables filtering triaged vs. untriaged findings in Excel/Google Sheets for:

- Progress tracking on security remediation
- Compliance documentation
- Team handoffs

**Enable CSV in jmo.yml:**

```yaml
outputs:
  - json       # Default
  - md         # Default
  - html       # Default
  - sarif      # Default
  - csv
```

**Or via CLI:**

```bash
jmo report results/ --outputs csv
```

**Use Cases:**

1. **Excel Analysis:**
   - Import CSV, create pivot tables by severity/tool
   - Filter findings by path patterns
   - Calculate severity distribution percentages

2. **Non-Technical Stakeholder Reports:**
   - Convert to formatted Excel with conditional formatting
   - Add charts for executive dashboards
   - Share via email (smaller than HTML)

3. **Compliance Auditing:**
   - Export findings for audit trails
   - Track remediation over time (compare CSVs)
   - Generate compliance metrics (OWASP, CWE counts)

4. **Data Science Workflows:**
   - Load into pandas/R for statistical analysis
   - Build ML models for false positive prediction
   - Trend analysis across multiple scans

**Performance:**

- <500ms for 10,000 findings
- ~200 KB file size for 1000 findings (vs ~500 KB JSON)
- Instant Excel import (no parsing delay)

## AI Integration

JMo Security integrates with AI assistants (GitHub Copilot, Claude Code) to accelerate vulnerability remediation via Model Context Protocol (MCP).

**Key Benefits:**

- **Query findings** by severity, tool, CWE, OWASP, or path patterns
- **Get full context** - AI reads vulnerable code, compliance mappings
- **Suggest fixes** - AI generates remediation code based on best practices
- **Track resolution** - Mark findings as fixed, false positive, or accepted risk

**Quick Start:**

```bash
# Start MCP server
jmo mcp-server --results-dir ./results

# Configure AI assistant (VS Code settings.json or Claude config)
{
  "mcpServers": {
    "jmo-security": {
      "command": "jmo",
      "args": ["mcp-server", "--results-dir", "./results"]
    }
  }
}
```

**MCP Tools Available:**

| Tool | Purpose |
|------|---------|
| `get_security_findings` | Query findings with filters |
| `apply_fix` | Apply AI-suggested remediation |
| `mark_resolved` | Track remediation status |
| `get_server_info` | Server status and metadata |

**Complete Guide:** [MCP_SETUP.md](MCP_SETUP.md)

## Historical Storage

Track security scans over time for trend analysis, regression detection, and compliance reporting using SQLite-based persistent storage.

**Key Features:**

- **SQLite Database** - Zero-configuration file-based storage (`.jmo/history.db`)
- **Full Finding History** - Stores all CommonFinding v1.2.0 fields
- **Git Integration** - Tracks commit hash, branch, tag, dirty status
- **Privacy-First** - Hostname/username collection opt-in only

**Quick Start:**

```bash
# Store scan results automatically
jmo scan --repo ./myapp --profile balanced --store-history

# View scan history
jmo history list

# Query stored findings
jmo history query --severity CRITICAL
```

**CLI Commands:**

| Command | Purpose |
|---------|---------|
| `jmo history store` | Store scan results in database |
| `jmo history list` | List all stored scans |
| `jmo history show` | Show details for a specific scan |
| `jmo history query` | Query findings from history |
| `jmo history compare` | Compare two scans side-by-side |
| `jmo history export` | Export to JSON/CSV |
| `jmo history verify` | Verify database integrity |
| `jmo history vacuum` | Optimize database |
| `jmo history prune` | Delete old scans |

**Complete Guide:** [HISTORY_GUIDE.md](HISTORY_GUIDE.md)

## Trend Analysis

Analyze security scan trends over time using statistical methods, detect regressions, and track developer remediation efforts.

**Key Features:**

- **Statistical Trend Detection** - Mann-Kendall test (p < 0.05) for significant trends
- **Regression Detection** - Identify new CRITICAL/HIGH findings between scans
- **Security Score** - Quantify security posture (0-100 scale) with letter grades (A-F)
- **Developer Attribution** - Track who fixed what using git blame integration

**Quick Start:**

```bash
# Run trend analysis (requires 2+ stored scans)
jmo trends analyze

# Analyze specific time period
jmo trends analyze --days 30

# Export to JSON for dashboards
jmo trends analyze --format json --output trends.json
```

**CLI Commands:**

| Command | Purpose |
|---------|---------|
| `jmo trends analyze` | Run trend analysis |
| `jmo trends show` | Show scan context window |
| `jmo trends regressions` | Detect security regressions |
| `jmo trends score` | Get security score |
| `jmo trends compare` | Compare two specific scans |
| `jmo trends insights` | Get automated insights |
| `jmo trends explain` | Explain terminology (Mann-Kendall, etc.) |
| `jmo trends developers` | Developer attribution analysis |

**Complete Guide:** [TRENDS_GUIDE.md](TRENDS_GUIDE.md)

## Machine-Readable Diffs

**Compare two security scans to identify new, resolved, and modified findings.**

The `jmo diff` command enables intelligent comparison of scan results using fingerprint-based matching, supporting PR reviews, CI/CD gates, remediation tracking, and trend analysis.

**Key Features:**

- **Fingerprint Matching**: O(n) performance with stable finding IDs
- **Four Classifications**: NEW, RESOLVED, UNCHANGED, MODIFIED
- **Modification Detection**: Tracks severity upgrades, compliance changes, priority shifts
- **Four Output Formats**: JSON, Markdown (PR comments), HTML (interactive), SARIF 2.1.0

**Quick Start:**

```bash
# Compare two scan result directories
jmo diff baseline-results/ current-results/ --format md --output pr-diff.md

# Compare historical scans from SQLite database
jmo diff --scan abc123-baseline --scan def456-current --format json

# CI gate: fail on new HIGH/CRITICAL findings
jmo diff baseline/ current/ --format json --fail-on HIGH --only new
```

**CLI Commands:**

| Command | Purpose |
|---------|---------|
| `jmo diff <baseline> <current>` | Compare two result directories |
| `jmo diff --scan ID1 --scan ID2` | Compare historical scans from database |
| `--format md\|json\|html\|sarif` | Output format selection |
| `--only new\|resolved\|modified` | Filter by change category |
| `--fail-on SEVERITY` | Exit 1 if new findings at severity |

**Complete Guide:** [DIFF_GUIDE.md](DIFF_GUIDE.md)


## SLSA Attestation

**Supply chain attestation using SLSA provenance and Sigstore keyless signing.**

Proves who scanned what, when, and with which tools - making scan results tamper-evident and verifiable. Target compliance: SLSA Level 2.

**Key Benefits:**

- **Tamper Evidence**: Detect if scan results were modified after generation
- **Audit Trail**: Full provenance (commit, tools, profile, CI environment)
- **Compliance**: Meet SOC 2, ISO 27001, PCI DSS supply chain requirements
- **Keyless Signing**: Sigstore OIDC - no key management, uses GitHub/GitLab identity
- **Public Transparency**: Rekor transparency log provides independent verification

**Quick Start:**

```bash
# Generate attestation
jmo attest results/summaries/findings.json

# Sign with Sigstore (requires CI environment)
jmo attest results/summaries/findings.json --sign

# Verify attestation
jmo verify findings.json findings.json.att.json

# Verify with signature and Rekor check
jmo verify findings.json findings.json.att.json \
  --signature findings.json.att.sigstore.json --check-rekor
```

**CLI Commands:**

| Command | Purpose |
|---------|---------|
| `jmo attest <file>` | Generate SLSA provenance attestation |
| `jmo attest <file> --sign` | Generate and sign with Sigstore |
| `jmo verify <file> <attestation>` | Verify attestation integrity |
| `--enable-tamper-detection` | Enable advanced tamper checks |
| `--check-rekor` | Verify against Rekor transparency log |

**Complete Guide:** [SLSA_GUIDE.md](SLSA_GUIDE.md)


## OS notes (installing tools)

**Recommended:** Use `jmo tools` for cross-platform tool management:

```bash
# Check what's installed/missing
jmo tools check --profile balanced

# Install missing tools (cross-platform, automatic method selection)
jmo tools install --profile balanced

# Update outdated tools
jmo tools update
```

See [Tool Management](#tool-management) for complete documentation.

**Alternative methods:**

- macOS: `brew install semgrep trivy syft checkov hadolint && brew install --cask owasp-zap && brew install trufflesecurity/trufflehog/trufflehog`
- Linux: use apt/yum/pacman for basics; use official install scripts for trivy/syft; use pipx for Python-based tools like checkov/semgrep

You can run with `--allow-missing-tools` to generate empty stubs for any tools you haven't installed yet.

**SHA256 Verification for Homebrew (macOS):**

JMo provides defense-in-depth for macOS developer environments by verifying the Homebrew installer before execution:

1. Downloads Homebrew installer to temp file (no immediate execution)
2. Displays SHA256 hash for manual verification
3. Provides verification link: <https://github.com/Homebrew/install/blob/HEAD/install.sh>
4. Validates downloaded file is not empty
5. Only executes after verification

**Why this matters:** Mitigates supply chain risks by ensuring Homebrew installer hasn't been tampered with during transit or by a compromised mirror.

**Example output during `jmo tools install` on macOS:**

```bash
Homebrew not found. Installing Homebrew...
Download SHA256: a1b2c3d4e5f6g7h8...
Verify at: https://github.com/Homebrew/install/blob/HEAD/install.sh
Press Enter to continue after verifying, or Ctrl+C to cancel...
```

### Nosey Parker on WSL (native recommended) and auto-fallback (Docker)

On Windows Subsystem for Linux (WSL), the most reliable approach is a native Nosey Parker install. Prebuilt binaries can fail on older glibc; building from source works well.

Native (WSL/Linux) install steps:

```bash
# 1) Prereqs
sudo apt-get update -y
sudo apt-get install -y build-essential pkg-config libssl-dev libsqlite3-dev zlib1g-dev libboost-all-dev

# Ensure a recent CMake (>= 3.18) is available; upgrade if needed for your distro.
cmake --version || true

# 2) Rust toolchain
curl https://sh.rustup.rs -sSf | sh -s -- -y
source "$HOME/.cargo/env"

# 3) Build from source
git clone --depth=1 https://github.com/praetorian-inc/noseyparker /tmp/noseyparker-src
cd /tmp/noseyparker-src
cargo build --release

# 4) Put on PATH
mkdir -p "$HOME/.local/bin"
ln -sf "$PWD/target/release/noseyparker-cli" "$HOME/.local/bin/noseyparker"
echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
noseyparker --version
```

The CLI will use the local `noseyparker` binary when available. If it’s missing or fails to run, it automatically falls back to a Docker-based runner and writes:

```text
results/individual-repos/<repo-name>/noseyparker.json
```

Requirements for fallback: Docker running and access to `ghcr.io/praetorian-inc/noseyparker:latest`.

Manual invocation (optional):

```bash
bash scripts/core/run_noseyparker_docker.sh \
  --repo /path/to/repo \
  --out results/individual-repos/<repo-name>/noseyparker.json
```

You do not need to call this manually during normal `jmo scan/ci`; it’s used automatically if needed.

## CI and local verification

- Local “CI” bundle: `make verify` runs lint, tests, and a basic security sweep where configured.
- One‑shot CI flow: `jmo ci` combines scan + report and gates on `--fail-on`. Example:

```bash
jmo ci --repos-dir ~/repos --profile-name balanced --fail-on HIGH --profile
```

Outputs include: `summaries/findings.json`, `SUMMARY.md`, `findings.yaml`, `findings.sarif`, `dashboard.html`, and `timings.json` (when profiling).

### CI/CD Pipeline Integration Strategy

**Recommended multi-stage approach for security scanning in CI/CD pipelines:**

#### Stage 1: Pre-Commit (Local Developer Workflow)

**Goal:** Fast feedback (< 30 seconds) to catch issues before commit

**Tools:**

- TruffleHog pre-commit hook (verified secrets only)
- Semgrep IDE plugins (real-time SAST)
- Hadolint pre-commit for Dockerfiles

**Setup:**

```bash
# Install pre-commit hooks
pip install pre-commit
pre-commit install

# .pre-commit-config.yaml example
repos:
  - repo: https://github.com/trufflesecurity/trufflehog
    rev: v3.84.2
    hooks:
      - id: trufflehog
        args: ['--only-verified', 'filesystem', '.']

  - repo: https://github.com/hadolint/hadolint
    rev: v2.12.0
    hooks:
      - id: hadolint
        args: ['--ignore', 'DL3008']
```

**Why:** Prevents secrets and obvious issues from entering the repository

---

#### Stage 2: Commit/PR Stage (Fast Feedback - Under 10 Minutes)

**Goal:** Quick validation for CI/CD gates using **fast profile**

**Profile:** `fast` (8 tools: trufflehog, semgrep, syft, trivy, checkov, hadolint, nuclei, shellcheck)

**Configuration:**

```yaml
# jmo.yml - fast profile
profiles:
  fast:
    tools: [trufflehog, semgrep, trivy]
    threads: 8
    timeout: 300
    per_tool:
      semgrep:
        flags: ["--exclude", "node_modules", "--exclude", ".git", "--exclude", "test"]
      trivy:
        flags: ["--no-progress", "--exit-code", "0"]
```

**CI Workflow (GitHub Actions):**

```yaml
name: Security Fast Scan
on: [pull_request, push]
jobs:
  security-fast:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4

      - name: Run Fast Security Scan
        run: |
          pip install jmo-security
          jmo ci --repo . --profile-name fast --fail-on HIGH --human-logs

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results/summaries/findings.sarif
```

**Expected Runtime:** 5-10 minutes
**Failure Criteria:** CRITICAL or HIGH severity findings

---

#### Stage 3: Build Stage (Comprehensive - 18-25 Minutes)

**Goal:** Complete coverage for merge/release using **balanced profile**

**Profile:** `balanced` (8 tools: trufflehog, semgrep, syft, trivy, checkov, hadolint, zap, nuclei)

**Configuration:**

```yaml
# jmo.yml - balanced profile
profiles:
  balanced:
    tools: [trufflehog, semgrep, syft, trivy, checkov, hadolint, zap, nuclei]
    threads: 4
    timeout: 600
    per_tool:
      zap:
        flags: ["-config", "api.disablekey=true", "-config", "spider.maxDuration=5"]
      trivy:
        flags: ["--no-progress", "--severity", "HIGH,CRITICAL"]
```

**CI Workflow (GitHub Actions):**

```yaml
name: Security Comprehensive Scan
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
jobs:
  security-comprehensive:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4

      - name: Run Balanced Security Scan
        run: |
          pip install "jmo-security[reporting]"
          jmo ci --repo . --profile-name balanced --fail-on HIGH --profile --human-logs

      - name: Upload Results as Artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-results
          path: |
            results/summaries/findings.json
            results/summaries/dashboard.html
            results/summaries/SUMMARY.md

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results/summaries/findings.sarif

      - name: Comment PR with Summary
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const summary = fs.readFileSync('results/summaries/SUMMARY.md', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '## 🔒 Security Scan Results\n\n' + summary
            });
```

**Expected Runtime:** 18-25 minutes
**Failure Criteria:** HIGH severity findings (configurable)

---

#### Stage 4: Nightly/Weekly Deep Audits (40-70 Minutes)

**Goal:** Maximum coverage with **deep profile** for compliance/audits

**Profile:** `deep` (28 tools: full suite including noseyparker, bandit, zap, nuclei, falco, afl++)

**Configuration:**

```yaml
# jmo.yml - deep profile
profiles:
  deep:
    tools: [trufflehog, noseyparker, semgrep, bandit, syft, trivy, checkov, hadolint, zap, nuclei, falco, afl++]
    threads: 2
    timeout: 900
    retries: 1
    per_tool:
      noseyparker:
        timeout: 1200
      afl++:
        timeout: 1800
        flags: ["-m", "none"]
```

**CI Workflow (Scheduled):**

```yaml
name: Security Deep Audit
on:
  schedule:
    - cron: '0 2 * * 0'  # Weekly Sunday 2 AM
  workflow_dispatch:      # Manual trigger
jobs:
  security-deep:
    runs-on: ubuntu-latest
    timeout-minutes: 90
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for noseyparker

      - name: Run Deep Security Audit
        run: |
          pip install "jmo-security[reporting]"
          jmo ci --repo . --profile-name deep --fail-on MEDIUM --profile --human-logs --allow-missing-tools

      - name: Upload Comprehensive Results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-deep-audit
          path: results/
          retention-days: 90

      - name: Send Slack Notification
        if: failure()
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "⚠️ Security Deep Audit Failed",
              "blocks": [
                {
                  "type": "section",
                  "text": {
                    "type": "mrkdwn",
                    "text": "Security deep audit found critical issues. Check <${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}|workflow run> for details."
                  }
                }
              ]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```

**Expected Runtime:** 40-70 minutes
**Failure Criteria:** MEDIUM severity or higher (more relaxed for deep audits)

---

#### Stage 5: Production/Runtime Monitoring (Continuous)

**Goal:** Continuous runtime security with Falco for Kubernetes/containers

**Tools:**

- Falco (eBPF-based runtime monitoring)
- Trivy continuous vulnerability monitoring

**Kubernetes Deployment:**

```yaml
# falco-daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: falco
  namespace: falco
spec:
  selector:
    matchLabels:
      app: falco
  template:
    metadata:
      labels:
        app: falco
    spec:
      serviceAccountName: falco
      hostNetwork: true
      hostPID: true
      containers:
      - name: falco
        image: falcosecurity/falco:latest
        securityContext:
          privileged: true
        volumeMounts:
        - mountPath: /host/var/run/docker.sock
          name: docker-socket
        - mountPath: /host/dev
          name: dev-fs
        - mountPath: /host/proc
          name: proc-fs
          readOnly: true
      volumes:
      - name: docker-socket
        hostPath:
          path: /var/run/docker.sock
      - name: dev-fs
        hostPath:
          path: /dev
      - name: proc-fs
        hostPath:
          path: /proc
```

**Alerting:**

- Falco alerts → Slack/PagerDuty for security events
- Trivy daily scans → Email/Jira tickets for new vulnerabilities

---

#### Performance Optimization Tips

**1. Caching Strategy:**

```yaml
# Cache tool installations between runs
- name: Cache Security Tools
  uses: actions/cache@v3
  with:
    path: |
      ~/.local/bin
      ~/.cache/semgrep
      ~/.cache/trivy
    key: security-tools-${{ runner.os }}-${{ hashFiles('.tool-versions') }}
```

**2. Incremental Scanning:**

```bash
# Scan only changed files in PRs (fast profile)
git diff --name-only origin/main... > changed-files.txt
jmo scan --repo . --profile-name fast --include-files changed-files.txt
```

**3. Parallel Execution:**

```yaml
# Run scans in parallel (independent stages)
jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - run: jmo scan --repo . --tools semgrep

  secrets:
    runs-on: ubuntu-latest
    steps:
      - run: jmo scan --repo . --tools trufflehog

  containers:
    runs-on: ubuntu-latest
    steps:
      - run: jmo scan --repo . --tools trivy
```

---

#### Summary Table

| Stage | Profile | Tools | Runtime | Trigger | Fail On |
|-------|---------|-------|---------|---------|------------|
| **Pre-commit** | N/A | TruffleHog, Semgrep IDE | < 30s | Local commit | Any finding |
| **Commit/PR** | fast | 8 tools | 5-10 min | Push, PR | HIGH+ |
| **Build** | balanced | 18 tools | 18-25 min | Main branch, PR | HIGH+ |
| **Deep Audit** | deep | 28 tools | 40-70 min | Weekly, manual | MEDIUM+ |
| **Runtime** | N/A | Falco, Trivy | Continuous | Always | CRITICAL |

**Key Principle:** Fail fast with fast profile in PR stage, comprehensive coverage in build stage, exhaustive audits weekly.

---

#### GitLab CI Quick Start

**See [docs/examples/.gitlab-ci.yml](examples/.gitlab-ci.yml) for complete configuration.**

Quick example for GitLab CI:

```yaml
# .gitlab-ci.yml
variables:
  JMO_PROFILE: "balanced"
  JMO_FAIL_ON: "HIGH"

security:scan:
  image: jmogaming/jmo-security:slim
  stage: security
  script:
    - jmo scan --repo . --profile-name ${JMO_PROFILE} --results-dir results --human-logs
    - jmo report results --fail-on ${JMO_FAIL_ON} --profile --human-logs
  artifacts:
    when: always
    paths:
      - results/
    reports:
      sast: results/summaries/findings.sarif
    expire_in: 30 days
```

**Key features:**

- Docker-based scanning (zero installation)
- Profile-based configuration (fast, slim, balanced, deep)
- SARIF upload for GitLab Security Dashboard
- Multi-target support (repositories, containers, IaC, URLs)

---

#### Jenkins Quick Start

**See [docs/examples/Jenkinsfile](examples/Jenkinsfile) for complete configuration.**

Quick example for Jenkins:

```groovy
// Jenkinsfile
pipeline {
    agent any
    environment {
        JMO_IMAGE = 'jmogaming/jmo-security:slim'
        JMO_PROFILE = 'balanced'
        JMO_FAIL_ON = 'HIGH'
    }
    stages {
        stage('Security Scan') {
            agent {
                docker {
                    image "${JMO_IMAGE}"
                    args '-v $WORKSPACE:/workspace -w /workspace'
                }
            }
            steps {
                sh """
                    jmo scan --repo . --profile-name ${JMO_PROFILE} --results-dir results --human-logs
                    jmo report results --fail-on ${JMO_FAIL_ON} --profile --human-logs
                """
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'results/**/*', allowEmptyArchive: true
            publishHTML([
                reportDir: 'results/summaries',
                reportFiles: 'dashboard.html',
                reportName: 'JMo Security Dashboard'
            ])
        }
    }
}
```

**Key features:**

- Docker-based execution for zero-installation
- HTML dashboard publishing in Jenkins UI
- Artifact archiving with 30-day retention
- Multi-target scanning support

---

### Interpreting CI failures (deeper guide)

Common failure modes in `.github/workflows/tests.yml` and how to fix them:

- Workflow validation (actionlint)
  - Symptom: step “Validate GitHub workflows (actionlint)” fails early.
  - Why: Invalid `uses:` reference, missing version tag, or schema errors.
  - Fix locally: run `pre-commit run actionlint --all-files`. See the action: <https://github.com/rhysd/actionlint> and our workflow at `.github/workflows/tests.yml`.

- Pre-commit hooks (YAML/format/lint)
  - Symptom: pre-commit step fails on YAML (`yamllint`), markdownlint, ruff/black, or shell checks.
  - Fix locally: `make pre-commit-run` or run individual hooks. Config lives in `.pre-commit-config.yaml`; YAML rules in `.yamllint.yaml`; ruff/black use defaults in this repo. Docs: <https://pre-commit.com/>

- Test coverage threshold not met
  - Symptom: Tests pass, but `--cov-fail-under=85` fails the job.
  - Fix locally: run `pytest -q --maxfail=1 --disable-warnings --cov=. --cov-report=term-missing` to identify gaps, then add tests. High‑leverage areas include adapters' malformed/empty JSON handling and reporters' edge cases. Pytest‑cov docs: <https://pytest-cov.readthedocs.io/>

- Codecov upload warnings (tokenless OIDC)
  - Symptom: Codecov step asks for a token or indicates OIDC not enabled.
  - Context: Public repos usually don’t require `CODECOV_TOKEN`. This repo uses tokenless OIDC with `codecov/codecov-action@v5` and minimal permissions (`contents: read`).
  - Fix: Ensure `coverage.xml` exists (the tests step emits it) and confirm OIDC is enabled in your Codecov org/repo. Action docs: <https://github.com/codecov/codecov-action> and OIDC docs: <https://docs.codecov.com/docs/tokenless-uploads>

- Canceled runs (concurrency)
  - Symptom: A run is marked “canceled.”
  - Why: Concurrency is enabled to cancel in‑progress runs on rapid pushes. Re‑run or push again once ready.

- Matrix differences (Ubuntu vs macOS)
  - Symptom: Step passes on one OS but fails on another.
  - Tips: Confirm tool availability/paths on macOS (Homebrew), line endings, and case‑sensitive paths. Use conditional install steps if needed.

If the failure isn't listed, expand the step logs in GitHub Actions for detailed stderr/stdout. When opening an issue, include the exact failing step and error snippet.

## General Troubleshooting

### Enhanced Debug Logging

JMo provides comprehensive exception logging for faster troubleshooting. Enable with `--log-level DEBUG`:

```bash
jmo scan --repos-dir ~/repos --log-level DEBUG
jmo wizard --log-level DEBUG
```

**What you get:**

- **GitLab scanner:** Clone failures, token errors, image scan errors, cleanup errors
- **Wizard:** URL validation failures (HTTP errors, timeouts, DNS), IaC file type detection errors, K8s context validation errors
- **Adapters:** JSON parse failures with fallback behavior (Nuclei, Falco, TruffleHog)
- **Detailed stack traces:** Full exception context for all errors

**Example output:**

```text
[DEBUG] GitLab clone failed for mygroup/myrepo: HTTPError 401 (Invalid token)
[DEBUG] Nuclei: Skipped empty line at index 42
[DEBUG] TruffleHog: JSON parse failed, falling back to NDJSON
```

**When to use:**

- Scans failing with unclear errors
- Tools returning no findings unexpectedly
- Investigating timeouts or hangs
- Troubleshooting multi-target scanning

Tools not found

- Run `jmo tools check` to see tool status, then `jmo tools install --profile balanced` to install; use `--allow-missing-tools` for exploratory runs.

No repositories to scan

- Ensure you passed `--repo`, `--repos-dir`, or `--targets`; when using `--repos-dir`, only immediate subfolders are considered.

Slow scans

- Reduce the toolset via a lighter profile (`fast`), or increase threads; use `report --profile` to inspect `timings.json` and adjust.

YAML reporter missing

- If PyYAML isn’t installed, YAML output is skipped with a DEBUG log; install `pyyaml` to enable.

Permission denied on scripts

- Ensure scripts are executable: `find scripts -type f -name "*.sh" -exec chmod +x {} +`

Hadolint shows no results

- Hadolint only runs when a `Dockerfile` exists at the repo root; this is expected. With `--allow-missing-tools`, a stub may be created when appropriate so reporting still works.

TruffleHog output looks empty

- Depending on flags and repo history, TruffleHog may stream JSON objects rather than a single array. The CLI captures and writes this stream verbatim; empty output is valid if no secrets are detected.

## Reference: CLI synopsis

Scan (with multi-target support)

```bash
jmo scan [--repo PATH | --repos-dir DIR | --targets FILE] \
  [--image IMAGE | --images-file FILE] \
  [--terraform-state FILE | --cloudformation FILE | --k8s-manifest FILE] \
  [--url URL | --urls-file FILE | --api-spec FILE_OR_URL] \
  [--gitlab-repo REPO | --gitlab-group GROUP] [--gitlab-url URL] [--gitlab-token TOKEN] \
  [--k8s-context CONTEXT] [--k8s-namespace NS | --k8s-all-namespaces] \
  [--results-dir DIR] [--config FILE] [--tools ...] [--timeout SECS] [--threads N] \
  [--allow-missing-tools] [--profile-name NAME] [--log-level LEVEL] [--human-logs]
```

Report

```bash
jmo report RESULTS_DIR [--out DIR] [--config FILE] [--fail-on SEV] [--profile] \
  [--threads N] [--log-level LEVEL] [--human-logs]
```

CI (scan + report with multi-target support)

```bash
jmo ci [--repo PATH | --repos-dir DIR | --targets FILE] \
  [--image IMAGE | --images-file FILE] \
  [--terraform-state FILE | --cloudformation FILE | --k8s-manifest FILE] \
  [--url URL | --urls-file FILE | --api-spec FILE_OR_URL] \
  [--gitlab-repo REPO | --gitlab-group GROUP] [--gitlab-url URL] [--gitlab-token TOKEN] \
  [--k8s-context CONTEXT] [--k8s-namespace NS | --k8s-all-namespaces] \
  [--results-dir DIR] [--config FILE] [--tools ...] [--timeout SECS] [--threads N] \
  [--allow-missing-tools] [--profile-name NAME] [--fail-on SEV] [--profile] \
  [--policy NAME] [--fail-on-policy-violation] [--strict-versions] \
  [--log-level LEVEL] [--human-logs]
```

Trends (Statistical trend analysis)

```bash
# Main analysis command
jmo trends analyze [--branch NAME] [--since TIMESTAMP] [--scans N] [--min-scans N] \
  [--format terminal|json|html] [--output FILE] [--db PATH] \
  [--export csv|prometheus|grafana|dashboard] [--export-file FILE]

# Show scan context window
jmo trends show [SCAN_ID] [--window N] [--branch NAME] [--format terminal|json] [--db PATH]

# Detect regressions
jmo trends regressions [--scan-id ID] [--branch NAME] [--severity LEVEL] \
  [--format terminal|json] [--db PATH]

# Security score
jmo trends score [--branch NAME] [--scans N] [--format terminal|json] [--db PATH]

# Compare two scans
jmo trends compare SCAN_ID_1 SCAN_ID_2 [--format terminal|json] [--db PATH]

# Automated insights
jmo trends insights [--branch NAME] [--scans N] [--format terminal|json] [--db PATH]

# Explain terminology
jmo trends explain [mann-kendall|security-score|regression|trends|all]

# Developer attribution
jmo trends developers [--scan-id ID] [--branch NAME] [--format terminal|json] \
  [--team-map FILE] [--velocity] [--db PATH]
```

Diff (Machine-readable diff)

```bash
jmo diff BASELINE_DIR CURRENT_DIR [--format terminal|json|md|sarif|html] \
  [--output FILE] [--fail-on NEW_CRITICAL|NEW_HIGH] [--severity-filter LEVEL] \
  [--show-context] [--attribution]
```

---

Happy scanning!

**Last Updated:** December 2025
