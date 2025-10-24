# JMO Security Suite — User Guide

This guide walks you through everything from a 2‑minute quick start to advanced configuration. Simple tasks are at the top; deeper features follow.

Note: The CLI is available as the console command `jmo` (via PyPI) and also as a script at `scripts/cli/jmo.py` in this repo. The examples below use the `jmo` command, but you can replace it with `python3 scripts/cli/jmo.py` if running from source.

If you're brand new, you can also use the beginner‑friendly wrapper `jmotools` described below.

## ✨ Recent Improvements

### HTML Dashboard v2: Actionable Findings & Enhanced UX (October 15, 2025)

**Major Enhancement:** Transformed dashboard from "good detection" to "actionable remediation platform"

**Key Features:**

- 🎯 **Code Context**: Expandable rows show syntax-highlighted code snippets (2-5 lines) right in the dashboard
- 🔧 **Suggested Fixes**: Copy-paste ready fixes from Semgrep autofix with one-click copy button
- 🔑 **Secret Context**: Full secret details with commit/author/entropy for rotation workflows
- 📊 **Grouping Modes**: Group by File | Rule | Tool | Severity with collapsible groups
- 🔍 **Enhanced Filters**: CWE/OWASP filters, path patterns, multi-select severity
- ✅ **Triage Workflow**: Bulk actions, localStorage persistence, export to `triage.json`
- 🏷️ **Risk Metadata**: CWE/OWASP badges with tooltips, confidence indicators

**Schema Evolution:** CommonFinding v1.1.0 adds `context`, `risk`, `secretContext`, enhanced `remediation`

**Impact:** 50% faster triage, 70% faster fixes, 80% noise reduction

### Phase 1 (October 2025)

**Security & Code Quality:**

- 🔒 **XSS vulnerability patched** in HTML dashboard with comprehensive input escaping
- 🛡️ **OSV scanner fully integrated** for open-source vulnerability detection
- ⚙️ **Type-safe severity enum** with comparison operators for cleaner, more maintainable code
- 🔄 **Backward-compatible suppression keys** supporting both `suppressions` (recommended) and `suppress` (legacy)

**Enhanced Features:**

- 📊 **Enriched SARIF 2.1.0 output** with CWE/OWASP/CVE taxonomies, code snippets, and CVSS scores
- 🎯 **Configurable thread recommendations** via `jmo.yml` profiling section
- 📝 **Magic numbers extracted** to named constants (FINGERPRINT_LENGTH, MESSAGE_SNIPPET_LENGTH)

**Quality Metrics:**

- ✅ 140/140 tests passing
- ✅ 74% code coverage (adapters/reporters focus)
- ✅ No breaking changes to existing workflows

See [CHANGELOG.md](../CHANGELOG.md) for complete details.

## Quick start (2 minutes)

Prereqs: Linux, WSL, or macOS with Python 3.10+ recommended (3.8+ supported).

1. Install the CLI

```bash
# Preferred (isolated):
pipx install "jmo-security[reporting]"

# Or using pip (user site):
pip install --user "jmo-security[reporting]"
```

The `reporting` extra bundles PyYAML and jsonschema so YAML output and schema validation work automatically. If you only need JSON/Markdown/SARIF, install the base package (`jmo-security`) instead.

1. Verify your environment and get install tips for optional tools

```bash
make verify-env
```

1. Run a fast multi-repo scan + report in one step

```bash
# Scan all immediate subfolders under ~/repos with the default (balanced) profile
jmo ci --repos-dir ~/repos --fail-on HIGH --profile --human-logs

# Open the dashboard
xdg-open results/summaries/dashboard.html  # Linux
open results/summaries/dashboard.html       # macOS
```

Outputs are written under `results/` by default, with unified summaries in `results/summaries/` (JSON/MD/YAML/HTML/SARIF). SARIF is enabled by default via `jmo.yml`.

### Beginner mode: jmotools wrapper (optional, simpler commands)

Prefer memorable commands that verify tools, optionally clone from a TSV, run the right profile, and open results at the end? Use `jmotools`:

```bash
# Quick fast scan (auto-opens results)
jmotools fast --repos-dir ~/security-testing

# Deep/full scan using the curated 'deep' profile
jmotools full --repos-dir ~/security-testing --allow-missing-tools

# Clone from TSV first, then balanced scan
jmotools balanced --tsv ./candidates.tsv --dest ./repos-tsv

# Bootstrap and verify curated tools (Linux/WSL/macOS)
jmotools setup --check
jmotools setup --auto-install
```

Makefile shortcuts are also available:

```bash
make setup             # jmotools setup --check (installs package if needed)
make fast DIR=~/repos  # jmotools fast --repos-dir ~/repos
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

Tip: You can also run `make tools` to install/upgrade the curated external scanners (trufflehog, semgrep, trivy, syft, checkov, bandit, hadolint, zap, noseyparker, falco, afl++, etc.) and `make verify-env` to validate your setup.

## Multi-Target Scanning (v0.6.0+)

**New in v0.6.0:** Scan beyond local repositories to cover your entire infrastructure.

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

**Tools used (v0.6.2):**

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

**Tools used (v0.6.2):** Full repository scanner (TruffleHog, Semgrep, Bandit, Trivy, Syft, Checkov, Hadolint, Noseyparker, Falco, AFL++)

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
├── individual-images/         # Container image scans (v0.6.0)
│   └── nginx_latest/
│       ├── trivy.json
│       └── syft.json
├── individual-iac/            # IaC file scans (v0.6.0)
│   └── infrastructure/
│       ├── checkov.json
│       └── trivy.json
├── individual-web/            # Web URL scans (v0.6.0)
│   └── example_com/
│       └── zap.json
├── individual-gitlab/         # GitLab repository scans (v0.6.0)
│   └── mygroup_myrepo/
│       └── trufflehog.json
├── individual-k8s/            # Kubernetes cluster scans (v0.6.0)
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
# Fast profile for quick feedback (3 tools, 300s timeout)
jmo scan --image nginx:latest --profile-name fast

# Deep profile for comprehensive audits (12 tools, 900s timeout)
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

**Note (v0.6.2):**

- **GitLab Repos** now run full repository scanner (10/12 tools) instead of TruffleHog-only
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

Unified summaries live in `results/summaries/`:

- findings.json — Machine‑readable normalized findings
- **SUMMARY.md — Enhanced Markdown summary** (see below)
- findings.yaml — Optional YAML (if PyYAML available)
- dashboard.html — Self‑contained interactive dashboard
- findings.sarif — SARIF 2.1.0 output (enabled by default)
- timings.json — Present when `jmo report --profile` is used
- SUPPRESSIONS.md — Summary of filtered IDs when suppressions are applied

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

## Configuration (jmo.yml)

`jmo.yml` controls what runs and how results are emitted. Top‑level fields supported by the CLI include:

- tools: [trufflehog, noseyparker, semgrep, syft, trivy, checkov, hadolint, zap, nuclei, falco, afl++, bandit]
  - Note (v0.6.2): Added Nuclei for API security scanning (CVEs, misconfigurations, 4000+ templates)
  - Note (v0.5.0): Removed deprecated tools (gitleaks, tfsec, osv-scanner). Added DAST (zap), runtime security (falco), and fuzzing (afl++)
- outputs: [json, md, yaml, html, sarif]
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
outputs: [json, md, yaml, html, sarif]
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

### Telemetry Configuration (v0.7.0+)

JMo Security can collect anonymous usage statistics to help prioritize features and improve the tool. Telemetry is **disabled by default** (opt-in only) and fully respects your privacy with a privacy-first, opt-in design.

#### What We Collect (Anonymous Only)

✅ **What we collect:**

- Tool usage (which tools ran)
- Scan duration (bucketed: <5min, 5-15min, etc.)
- Execution mode (CLI/Docker/Wizard)
- Platform (Linux/macOS/Windows)
- Profile selected (fast/balanced/deep)
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
jmotools wizard

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

- **MVP (v0.7.0):** GitHub Gist (private, append-only JSONL)
- **Future (v0.8.0+):** Cloudflare Workers for scale (when >10k users)

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

## Key CLI commands and flags

Subcommands: scan, report, ci

Common flags:

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

File format (supports both `suppressions` and legacy `suppress` keys):

```yaml
# Recommended format (new):
suppressions:

  - id: abcdef1234567890
    reason: false positive (hashing rule)
    expires: 2025-12-31   # optional ISO date; omit to never expire

  - id: 9999deadbeef
    reason: accepted risk for demo

# Legacy format (still supported for backward compatibility):
suppress:

  - id: abcdef1234567890
    reason: false positive (hashing rule)
    expires: 2025-12-31
```

Behavior:

- Active suppressions remove matching findings from outputs.
- A suppression summary (`SUPPRESSIONS.md`) is written alongside summaries listing the filtered IDs.
- The tool automatically detects which key (`suppressions` or `suppress`) is present in your config.

Search order for the suppression file is: `<results_dir>/jmo.suppress.yml` first, then `./jmo.suppress.yml` in the current working directory.

## SARIF and HTML dashboard

### SARIF 2.1.0 Output (Enriched)

- SARIF emission is enabled by default in this repo (`outputs: [json, md, yaml, html, sarif]`). If you remove `sarif` from outputs, SARIF won't be written.
- **Enhanced in Phase 1:** SARIF output now includes:
  - **Code snippets** in region context for better IDE integration
  - **CWE/OWASP/CVE taxonomy references** for security categorization
  - **CVSS scores and metadata** for vulnerability prioritization
  - **Richer rule descriptions** and fix suggestions
  - **Improved GitHub/GitLab code scanning integration**

### HTML Dashboard v2 (Enhanced UX)

The HTML dashboard (`dashboard.html`) is a fully self-contained, zero-dependency interactive interface for exploring findings. **October 2025 v2 redesign** transforms it into an actionable remediation platform.

#### Core Features

**Traditional Features (v1.0):**

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

#### Backward Compatibility

- **CommonFinding v1.0.0** findings still render correctly
- **All v1.1.0 fields are optional**: Adapters gracefully degrade if fields missing
- **Progressive enhancement**: Dashboard detects schema version and enables features accordingly

## OS notes (installing tools)

Run `make verify-env` to detect your OS/WSL and see smart install hints. Typical options:

- macOS: `brew install semgrep trivy syft checkov hadolint && brew install --cask owasp-zap && brew install trufflesecurity/trufflehog/trufflehog`
- Linux: use apt/yum/pacman for basics; use official install scripts for trivy/syft; use pipx for Python‑based tools like checkov/semgrep; see hints printed by `verify-env`.

You can run with `--allow-missing-tools` to generate empty stubs for any tools you haven’t installed yet.

Curated installer:

```bash
make tools           # install core scanners
make tools-upgrade   # upgrade/refresh installed scanners
make verify-env      # detect OS/WSL/macOS and show install hints
```

**SHA256 Verification for Homebrew (macOS, v0.7.1+):**

v0.7.1 adds defense-in-depth for macOS developer environments by verifying the Homebrew installer before execution:

1. Downloads Homebrew installer to temp file (no immediate execution)
2. Displays SHA256 hash for manual verification
3. Provides verification link: https://github.com/Homebrew/install/blob/HEAD/install.sh
4. Validates downloaded file is not empty
5. Only executes after verification

**Why this matters:** Mitigates supply chain risks by ensuring Homebrew installer hasn't been tampered with during transit or by a compromised mirror.

**Example output during `make tools` on macOS:**
```
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

**Profile:** `fast` (3 tools: trufflehog, semgrep, trivy)

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

**Expected Runtime:** 5-8 minutes
**Failure Criteria:** CRITICAL or HIGH severity findings

---

#### Stage 3: Build Stage (Comprehensive - 15-30 Minutes)

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

**Expected Runtime:** 15-20 minutes
**Failure Criteria:** HIGH severity findings (configurable)

---

#### Stage 4: Nightly/Weekly Deep Audits (30-60 Minutes)

**Goal:** Maximum coverage with **deep profile** for compliance/audits

**Profile:** `deep` (12 tools: full suite including noseyparker, bandit, zap, nuclei, falco, afl++)

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

**Expected Runtime:** 30-60 minutes
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
| **Commit/PR** | fast | 3 tools | 5-8 min | Push, PR | HIGH+ |
| **Build** | balanced | 8 tools | 15-20 min | Main branch, PR | HIGH+ |
| **Deep Audit** | deep | 12 tools | 30-60 min | Weekly, manual | MEDIUM+ |
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
- Profile-based configuration (fast, balanced, deep)
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

If the failure isn’t listed, expand the step logs in GitHub Actions for detailed stderr/stdout. When opening an issue, include the exact failing step and error snippet.

## Troubleshooting

### Enhanced Debug Logging (v0.7.1+)

v0.7.1 adds comprehensive exception logging for faster troubleshooting. Enable with `--log-level DEBUG`:

```bash
jmo scan --repos-dir ~/repos --log-level DEBUG
jmotools wizard --log-level DEBUG
```

**What you get:**
- **GitLab scanner:** Clone failures, token errors, image scan errors, cleanup errors
- **Wizard:** URL validation failures (HTTP errors, timeouts, DNS), IaC file type detection errors, K8s context validation errors
- **Adapters:** JSON parse failures with fallback behavior (Nuclei, Falco, TruffleHog)
- **Detailed stack traces:** Full exception context for all errors

**Example output:**
```
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

- Run `make verify-env` for detection and install hints, or install missing tools; use `--allow-missing-tools` for exploratory runs.

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

Scan (v0.6.0+ with multi-target support)

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

CI (scan + report with v0.6.0 multi-target support)

```bash
jmo ci [--repo PATH | --repos-dir DIR | --targets FILE] \
  [--image IMAGE | --images-file FILE] \
  [--terraform-state FILE | --cloudformation FILE | --k8s-manifest FILE] \
  [--url URL | --urls-file FILE | --api-spec FILE_OR_URL] \
  [--gitlab-repo REPO | --gitlab-group GROUP] [--gitlab-url URL] [--gitlab-token TOKEN] \
  [--k8s-context CONTEXT] [--k8s-namespace NS | --k8s-all-namespaces] \
  [--results-dir DIR] [--config FILE] [--tools ...] [--timeout SECS] [--threads N] \
  [--allow-missing-tools] [--profile-name NAME] [--fail-on SEV] [--profile] \
  [--log-level LEVEL] [--human-logs]
```

—

Happy scanning!
