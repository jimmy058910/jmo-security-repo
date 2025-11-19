# JMO Security Suite — User Guide

This guide walks you through everything from a 2‑minute quick start to advanced configuration. Simple tasks are at the top; deeper features follow.

Note: The CLI is available as the console command `jmo` (via PyPI) and also as a script at `scripts/cli/jmo.py` in this repo. The examples below use the `jmo` command, but you can replace it with `python3 scripts/cli/jmo.py` if running from source.

If you're brand new, you can also use the beginner‑friendly wrapper `jmotools` described below.

## ✨ Recent Improvements

### EPSS/KEV Risk Prioritization (v0.9.0, October 30, 2025)

**Major Enhancement:** Automatic CVE prioritization using real-world exploit data

**Key Features:**

- 🎯 **EPSS Integration**: Exploit probability scores (0-100%) from FIRST.org API with 7-day SQLite caching
- 🚨 **CISA KEV Detection**: Flags actively exploited CVEs with federal remediation deadlines
- 📊 **Priority Scoring**: Combines severity + EPSS + KEV status into actionable 0-100 priority score
- 🔍 **Enhanced Dashboard**: Priority column with color-coded badges, KEV indicators, sortable by priority
- 📝 **Priority Analysis Section**: SUMMARY.md shows KEV findings, high EPSS risks, priority distribution
- ⚡ **Bulk API Optimization**: Fetches all CVEs in single API call for speed

**Impact:** 40% faster triage by focusing on actively exploited CVEs first, 60% reduction in false prioritization

**Formula:** `priority = (severity_score × epss_multiplier × kev_multiplier) / 1.5` normalized to 0-100

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

## Package Manager Installation (v0.9.0+)

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

1. Verify your environment and get install tips for optional tools

```bash
make verify-env
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

**Note (v0.6.2):**

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

**v1.0.0:** All output formats use a metadata wrapper structure `{"meta": {...}, "findings": [...]}`. See [OUTPUT_FORMATS.md](OUTPUT_FORMATS.md) for complete specification.

Unified summaries live in `results/summaries/`:

- **findings.json** — Machine‑readable normalized findings (v1.0.0: includes metadata envelope)
- **findings.csv** — NEW in v1.0.0: Spreadsheet-friendly format with metadata header
- **SUMMARY.md** — Enhanced Markdown summary (see below)
- **findings.yaml** — Optional YAML (if PyYAML available, v1.0.0: includes metadata)
- **dashboard.html** — Interactive dashboard with dual-mode support (v1.0.0: inline ≤1000 findings, external >1000 findings)
- **findings.sarif** — SARIF 2.1.0 output (enabled by default)
- **timings.json** — Present when `jmo report --profile` is used
- **SUPPRESSIONS.md** — Summary of filtered IDs when suppressions are applied

**v1.0.0 Metadata Structure:**

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

### EPSS/KEV Risk Prioritization (v0.9.0+)

**New in v0.9.0:** JMo Security now automatically enriches CVE findings with EPSS (Exploit Prediction Scoring System) and CISA KEV (Known Exploited Vulnerabilities) data to help you prioritize remediation efforts based on real-world exploit activity.

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

## Cross-Tool Deduplication (v1.0.0)

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
  cross_tool_clustering: true  # Enable/disable
  similarity_threshold: 0.75   # Strictness (0.70-0.85)
```

### Best Practices

1. **Trust HIGH confidence findings first** - Multiple tools agreeing is strong signal
2. **Validate MEDIUM confidence** - 2 tools may still have false positives
3. **Review LOW confidence carefully** - Single tool detections need scrutiny
4. **Check duplicate findings** - Expand duplicates in dashboard to see all detections

### How the Algorithm Works

Cross-tool deduplication uses a multi-dimensional similarity algorithm combining:

- **Location (35%):** Path + line range overlap
- **Message (40%):** Fuzzy + token matching (e.g., "SQL injection" vs "SQL Injection vulnerability")
- **Metadata (25%):** CWE/CVE/Rule ID matching

Findings with ≥75% similarity are clustered together. The highest-severity finding becomes the representative, and others are attached as duplicates in `context.duplicates`.

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

- **Time:** <2 seconds for 1000 findings
- **Reduction:** 30-40% fewer reported findings (noise elimination)
- **Accuracy:** ≥85% clustering accuracy (validated on 200+ finding sample)

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

## Plugin System (v0.9.0+)

### Extensible architecture for custom security tool integrations

JMo Security uses a plugin-based architecture for all security tool adapters, enabling hot-reload during development, independent updates, and community-contributed integrations.

### Overview

All 28 security tools (26 Docker-ready) (TruffleHog, Semgrep, Trivy, Syft, Checkov, Hadolint, ZAP, Nuclei, Bandit, Nosey Parker, Falco, AFL++) are implemented as plugins using a standardized API.

**Key Benefits:**

- ✅ **Hot-Reload** - Edit adapter code without reinstalling JMo
- ✅ **Fast Development** - 4 hours → 1 hour per adapter (75% reduction)
- ✅ **Independent Updates** - Ship adapter improvements without core releases
- ✅ **Low-Risk Testing** - Test new tools in `~/.jmo/adapters/` without modifying core
- ✅ **Performance** - <100ms plugin loading overhead for all 12 adapters

### CLI Commands

**List all loaded plugins:**

```bash
jmo adapters list

# Output:
# Loaded 12 adapter plugins:
#   trivy           v1.0.0    Adapter for Aqua Security Trivy vulnerability scanner
#   semgrep         v1.0.0    Adapter for Semgrep multi-language SAST scanner
#   trufflehog      v1.0.0    Adapter for TruffleHog verified secrets detection
#   syft            v1.0.0    Adapter for Anchore Syft SBOM generator
#   checkov         v1.0.0    Adapter for Bridgecrew Checkov IaC scanner
#   hadolint        v1.0.0    Adapter for Hadolint Dockerfile linter
#   zap             v1.0.0    Adapter for OWASP ZAP DAST scanner
#   nuclei          v1.0.0    Adapter for ProjectDiscovery Nuclei vulnerability scanner
#   bandit          v1.0.0    Adapter for PyCQA Bandit Python SAST scanner
#   noseyparker     v1.0.0    Adapter for Nosey Parker secrets scanner
#   falco           v1.0.0    Adapter for Falco runtime security monitor
#   aflplusplus     v1.0.0    Adapter for AFL++ fuzzer
```

**Validate custom adapter:**

```bash
jmo adapters validate ~/.jmo/adapters/custom_tool_adapter.py

# Output:
# ✅ Valid plugin: /home/user/.jmo/adapters/custom_tool_adapter.py
#   Plugin: custom-tool v1.0.0
#   Metadata: OK
#   Methods: OK (parse, get_fingerprint)
#   Dependencies: OK
```

### Creating Custom Adapters

**Plugin Search Paths:**

1. `~/.jmo/adapters/` - User plugins (highest priority)
2. `scripts/core/adapters/` - Built-in plugins (12 official adapters)

**Quick Example:**

```python
# ~/.jmo/adapters/snyk_adapter.py
from pathlib import Path
from typing import List
from scripts.core.plugin_api import AdapterPlugin, Finding, PluginMetadata, adapter_plugin
import json

@adapter_plugin(PluginMetadata(
    name="snyk",  # CRITICAL: Must match snyk.json filename
    version="1.0.0",
    author="Your Name",
    description="Adapter for Snyk SCA scanner",
    tool_name="snyk",
    schema_version="1.2.0",
    output_format="json",
    exit_codes={0: "clean", 1: "findings", 2: "error"}
))
class SnykAdapter(AdapterPlugin):
    @property
    def metadata(self):
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path) -> List[Finding]:
        """Parse Snyk JSON output and return CommonFinding objects"""
        if not output_path.exists():
            return []

        findings = []
        with open(output_path) as f:
            data = json.load(f)

        for vuln in data.get("vulnerabilities", []):
            finding = Finding(
                schemaVersion="1.2.0",
                id="",  # Will be auto-generated
                ruleId=vuln["id"],
                severity=vuln["severity"].upper(),
                tool={
                    "name": "snyk",
                    "version": data.get("version", "unknown")
                },
                location={
                    "path": vuln.get("from", ["unknown"])[0],
                    "startLine": 1
                },
                message=vuln["title"],
                description=vuln.get("description", ""),
                remediation=vuln.get("fixedIn", "No fix available"),
                references=[{"url": vuln.get("url", "")}],
                raw=vuln  # Original Snyk payload
            )
            findings.append(finding)

        return findings
```

**Testing Your Adapter:**

```bash
# 1. Validate adapter
jmo adapters validate ~/.jmo/adapters/snyk_adapter.py

# 2. Run scan with your adapter
jmo scan --repo ./myapp --tools snyk --results-dir results

# 3. Verify findings
jmo report results --human-logs
```

**Hot-Reload Workflow:**

```bash
# Edit adapter (no reinstall needed)
vim ~/.jmo/adapters/snyk_adapter.py

# Run tests immediately - plugin auto-reloads
pytest tests/adapters/test_snyk_adapter.py -v

# Scan with updated adapter
jmo scan --repo ./myapp --tools snyk
```

### Plugin Architecture Details

**Components:**

1. **plugin_api.py** - Base classes and decorators
   - `Finding` dataclass (CommonFinding schema v1.2.0)
   - `PluginMetadata` dataclass
   - `AdapterPlugin` abstract base class
   - `@adapter_plugin` decorator

2. **plugin_loader.py** - Auto-discovery and loading
   - `PluginRegistry` (register/get/list/unregister)
   - `PluginLoader` (search paths, hot-reload)
   - Global functions: `discover_adapters()`, `get_plugin_registry()`

3. **normalize_and_report.py** - Integration point
   - Dynamically discovers adapters via `discover_adapters()`
   - Loads tool outputs using plugin registry
   - No hard-coded imports

**Performance:**

- Plugin loading: <10ms per adapter (~100ms total for 12 adapters)
- Hot-reload: Instant (no cache clearing needed)
- Memory overhead: Minimal (~5 MB for all 12 plugins)

### Advanced Usage

**Disable specific plugins:**

```python
# Custom script to unregister plugins
from scripts.core.plugin_loader import get_plugin_registry

registry = get_plugin_registry()
registry.unregister("obsolete-tool")  # Remove from registry
```

**List plugins programmatically:**

```python
from scripts.core.plugin_loader import discover_adapters, get_plugin_registry

discover_adapters()
registry = get_plugin_registry()

for name, plugin_class in registry.list().items():
    meta = plugin_class._plugin_metadata
    print(f"{meta.name} v{meta.version}: {meta.description}")
```

**Complete guide:** [CONTRIBUTING.md — Adding Tool Adapters](../CONTRIBUTING.md#adding-tool-adapters) | [.claude/skills/jmo-adapter-generator/SKILL.md](../.claude/skills/jmo-adapter-generator/SKILL.md)

## Schedule Management (v0.8.0+)

### Automate recurring security scans with Kubernetes-inspired scheduling

JMo Security v0.8.0 introduces a comprehensive schedule management system for automated, recurring scans with:

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

### Schedule CLI Commands (v0.9.0+)

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

- Profile-based scan job (fast/balanced/deep)
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

File format (supports both `suppressions` and legacy `suppress` keys):

```yaml
# Recommended format (new):
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

#### Dashboard Architecture

**All v1.1.0+ fields are optional**: Dashboard gracefully handles missing fields with progressive enhancement.

#### v1.0.0 Dual-Mode Architecture

**NEW in v1.0.0:** The HTML dashboard now automatically switches between two rendering modes based on dataset size to optimize performance and prevent browser freezing.

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

### CSV Reporter (v1.0.0+)

**NEW in v1.0.0:** Export findings to spreadsheet-friendly CSV format for Excel, Google Sheets, or data analysis workflows.

**Output File:** `results/summaries/findings.csv`

**Features:**

- **Metadata Header**: Scan information in comment rows (lines starting with `#`)
- **Standard CSV Format**: RFC 4180 compliant
- **UTF-8 Encoding**: Full Unicode support for international characters
- **Column Headers**: Severity, RuleID, Message, Location, Line, Tool, Version, ID

**Example Output:**

```csv
# JMo Security Findings Report - v1.0.0
# Generated: 2025-11-04T12:34:56Z
# Scan ID: scan-abc123
# Profile: balanced
# Tools: trivy, semgrep, trufflehog
# Targets: 5
# Findings: 42
# Platform: Linux

Severity,RuleID,Message,Location,Line,Tool,Version,ID
CRITICAL,github,GitHub Personal Access Token detected,config.py,15,trufflehog,3.63.0,trufflehog|github|config.py|15|def456
HIGH,CVE-2024-1234,Vulnerability in lodash,package.json,0,trivy,0.68.0,trivy|CVE-2024-1234|package.json|0|abc123
MEDIUM,python.lang.security.audit.dangerous-code-exec,Use of exec() detected,app.py,42,semgrep,1.45.0,semgrep|exec|app.py|42|ghi789
```

**Enable CSV in jmo.yml:**

```yaml
outputs:
  - json       # Default
  - md         # Default
  - html       # Default
  - sarif      # Default
  - csv        # NEW in v1.0.0
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

## AI Integration (v1.0.0+)

### AI-Powered Remediation via Model Context Protocol (MCP)

JMo Security integrates with AI assistants to accelerate vulnerability remediation. The MCP server provides AI with structured access to scan results, enabling intelligent analysis, fix suggestions, and remediation tracking.

### MCP Overview

**What is MCP?**

Model Context Protocol (MCP) is an open standard for connecting AI assistants to external data sources and tools. JMo's MCP server exposes security findings through a standardized API that works with GitHub Copilot, Claude Code, and any MCP-compatible AI.

**Key Benefits:**

- 🔍 **Query findings by severity, tool, CWE, OWASP, or path patterns**
- 🧠 **Get full context** - AI reads vulnerable code, commit history, and compliance mappings
- 🔧 **Suggest fixes** - AI generates remediation code based on industry best practices
- ✅ **Track resolution** - Mark findings as fixed, false positive, or accepted risk
- 📊 **Compliance analysis** - Automatic OWASP, CWE, NIST, PCI DSS, CIS framework mapping

### Integration Options

JMo Security supports two primary AI integrations:

#### 1. GitHub Copilot (VS Code)

**Best for:** Developers who use VS Code and GitHub Copilot for daily coding

**Quick Setup:**

```bash
# 1. Install JMo Security (if not already installed)
pip install jmo-security

# 2. Configure VS Code settings.json
{
  "github.copilot.chat.codeGeneration.useInstructionFiles": true,
  "github.copilot.mcp.servers": {
    "jmo-security": {
      "command": "jmo",
      "args": ["mcp-server", "--results-dir", "./results"]
    }
  }
}

# 3. Run a scan
jmo scan --repo ./myapp --results-dir ./results --profile balanced

# 4. Ask Copilot in VS Code:
# "What are the CRITICAL findings?"
# "Fix the SQL injection in src/api/db.py"
# "Show compliance mappings for finding abc123"
```

**Features:**

- In-editor remediation suggestions
- One-click fix application
- Contextual code analysis
- Real-time finding queries

📖 **Complete guide:** [docs/integrations/GITHUB_COPILOT.md](integrations/GITHUB_COPILOT.md)

#### 2. Claude Code (CLI/Terminal)

**Best for:** Terminal-first workflows, automation scripts, CI/CD integration

**Quick Setup:**

```bash
# 1. Install JMo Security
pip install jmo-security

# 2. Configure Claude Code MCP (~/.config/claude/config.json)
{
  "mcpServers": {
    "jmo-security": {
      "command": "jmo",
      "args": ["mcp-server", "--results-dir", "./results"]
    }
  }
}

# 3. Run scan
jmo scan --repos-dir ~/repos --results-dir ./results

# 4. Start MCP server in background
jmo mcp-server --results-dir ./results &

# 5. Use Claude Code CLI
claude "Analyze HIGH severity findings in src/api/"
claude "Suggest fixes for CWE-79 (XSS) findings"
```

**Features:**

- Terminal-native workflow
- Batch remediation scripting
- CI/CD integration
- Offline-first operation

📖 **Complete guide:** [docs/integrations/CLAUDE_CODE.md](integrations/CLAUDE_CODE.md)

### MCP Server Features

**4 MCP Tools:**

1. **`get_security_findings`** - Query findings with filters
   - Filters: `severity`, `tool`, `path`, `cwe`, `owasp`, `limit`, `offset`
   - Returns: Array of CommonFinding objects with full metadata
   - Example: `get_security_findings(severity="HIGH", path="src/api/*")`

2. **`apply_fix`** - Apply AI-suggested remediation to source code
   - Parameters: `finding_id`, `fix_content`, `dry_run`
   - Requires: `--enable-fixes` flag (read-only by default)
   - Validates: Syntax checking before applying changes

3. **`mark_resolved`** - Track remediation status
   - Parameters: `finding_id`, `status`, `comment`
   - Status options: `fixed`, `false_positive`, `accepted_risk`
   - Persists: Saves to `results/triage.json`

4. **`get_server_info`** - Server status and metadata
   - Returns: Total findings count, available finding IDs, scan timestamp
   - Used for: AI context and health checks

**1 MCP Resource:**

- **`finding://{id}`** - Full finding context including:
  - Source code snippet (20 lines of context)
  - Compliance framework mappings (OWASP, CWE, NIST, PCI DSS, CIS, ATT&CK)
  - Remediation guidance and references
  - Tool-specific metadata (CVSS scores, confidence ratings, etc.)

### Configuration

**Environment Variables:**

```bash
# Results directory (required)
export MCP_RESULTS_DIR="./results"

# Repository root for code context (optional)
export MCP_REPO_ROOT="$(pwd)"

# Enable write operations (apply_fix tool)
export MCP_ENABLE_FIXES="true"

# Logging level
export MCP_LOG_LEVEL="INFO"  # DEBUG, INFO, WARNING, ERROR
```

**Command-Line Flags:**

```bash
# Start MCP server
jmo mcp-server --results-dir ./results

# Enable fix suggestions (DANGEROUS - allows code modification)
jmo mcp-server --results-dir ./results --enable-fixes

# Custom repository root
jmo mcp-server --results-dir ./results --repo-root /path/to/repo

# Debug logging
jmo mcp-server --results-dir ./results --log-level DEBUG
```

### Usage Examples

#### Query Findings by Severity

```python
# AI Assistant (GitHub Copilot or Claude Code):
"Show me all CRITICAL findings"

# MCP call:
get_security_findings(severity="CRITICAL")

# Returns:
[
  {
    "id": "abc123...",
    "severity": "CRITICAL",
    "ruleId": "aws-credentials",
    "tool": {"name": "trufflehog", "version": "3.63.0"},
    "location": {"path": "config.yml", "startLine": 10},
    "message": "Hardcoded AWS credentials detected",
    "cwe": ["CWE-798"],
    "compliance": {
      "owaspTop10_2021": ["A02:2021"],
      "nistCsf2_0": ["PR.AC-1"],
      ...
    }
  }
]
```

#### Get Full Context for a Finding

```python
# AI Assistant:
"Show me the code around finding abc123"

# MCP resource access:
finding://abc123

# Returns:
{
  "finding": {...},  # Full CommonFinding object
  "codeContext": "5:   def authenticate(user):\n6:     # VULNERABLE CODE\n7:     password = 'hardcoded123'\n...",
  "remediation": {
    "summary": "Remove hardcoded credentials",
    "suggestions": ["Use environment variables", "Implement secrets manager"],
    "references": ["OWASP Secrets Management Cheat Sheet"]
  }
}
```

#### Apply AI-Suggested Fix

```python
# AI Assistant:
"Fix the SQL injection in src/api/users.py"

# Step 1: AI analyzes vulnerable code
finding://def456  # Get context

# Step 2: AI generates fix
fix_content = """
def get_user(user_id):
    # Use parameterized query to prevent SQL injection
    query = "SELECT * FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()
"""

# Step 3: Apply fix (requires --enable-fixes)
apply_fix(finding_id="def456", fix_content=fix_content, dry_run=False)

# Step 4: Mark as fixed
mark_resolved(finding_id="def456", status="fixed", comment="Applied parameterized query")
```

#### Compliance Framework Analysis

```python
# AI Assistant:
"Which findings map to OWASP A02:2021 (Cryptographic Failures)?"

# MCP call:
get_security_findings(owasp="A02:2021")

# Returns findings with:
compliance.owaspTop10_2021 = ["A02:2021"]
```

### Security & Privacy

**Read-Only by Default:**

- MCP server starts in **read-only mode**
- `get_security_findings`, `get_server_info`, `finding://` resource are always safe
- `apply_fix` requires explicit `--enable-fixes` flag (dangerous)

**Local Execution:**

- All data stays on your machine
- No external API calls (except AI assistant communication)
- Works offline after initial scan

**Results Directory Scoping:**

- MCP server only accesses specified `--results-dir`
- Cannot read files outside results directory (unless `--repo-root` provided)
- Repository root (`--repo-root`) used only for code context display

**Telemetry:**

- MCP integration respects JMo's telemetry settings
- If telemetry disabled (`JMO_TELEMETRY=0`), MCP server sends no analytics
- See [docs/TELEMETRY.md](TELEMETRY.md) for privacy policy

### Installation Methods

**Local Python (Recommended):**

```bash
pip install jmo-security
jmo mcp-server --results-dir ./results
```

**Docker Container:**

```bash
docker run -it --rm \
  -v "$(pwd)/results:/results:ro" \
  ghcr.io/jimmy058910/jmo-security:latest \
  mcp-server --results-dir /results
```

**Package Managers:**

```bash
# macOS/Linux
brew install jmo-security
jmo mcp-server --results-dir ./results

# Windows
winget install jmo.jmo-security
jmo mcp-server --results-dir ./results
```

### Troubleshooting

#### Error: "Results directory not found"

```bash
# Verify results directory exists
ls -la ./results/summaries/findings.json

# If missing, run a scan first
jmo scan --repo ./myapp --results-dir ./results
```

#### Error: "Permission denied when applying fix"

```bash
# Fix requires explicit enable flag
jmo mcp-server --results-dir ./results --enable-fixes

# Ensure you have write permissions to source files
chmod u+w src/api/users.py
```

#### Error: "MCP server not responding"

```bash
# Check server is running
ps aux | grep "jmo mcp-server"

# Check logs with debug mode
jmo mcp-server --results-dir ./results --log-level DEBUG

# Verify AI assistant configuration
# GitHub Copilot: Check VS Code settings.json
# Claude Code: Check ~/.config/claude/config.json
```

**No findings returned:**

```bash
# Verify findings.json exists and is valid
cat results/summaries/findings.json | jq

# Check MCP server can read results
jmo mcp-server --results-dir ./results --log-level DEBUG
# Look for "Loaded X findings from results/summaries/findings.json"
```

### MCP Advanced Configuration

**Custom Repository Root:**

By default, MCP server uses current directory as repository root. Specify custom path for multi-repo workflows:

```bash
jmo mcp-server \
  --results-dir ./results \
  --repo-root /path/to/actual/repo
```

**Multiple Results Directories:**

Scan multiple projects and aggregate findings:

```bash
# Scan multiple projects
jmo scan --repo ./backend --results-dir ./results-backend
jmo scan --repo ./frontend --results-dir ./results-frontend

# Start MCP server pointing to specific project
jmo mcp-server --results-dir ./results-backend
# Or switch to frontend
jmo mcp-server --results-dir ./results-frontend
```

**CI/CD Integration:**

Run MCP server in CI to enable AI-assisted triage:

```yaml
# .github/workflows/security-scan.yml
- name: Run security scan
  run: jmo scan --repo . --results-dir ./results --profile balanced

- name: Start MCP server for AI triage
  run: jmo mcp-server --results-dir ./results &

- name: AI-assisted remediation (optional)
  run: |
    # Use AI to suggest fixes for CRITICAL findings
    claude "Review CRITICAL findings and suggest fixes"
```

### Real-World Workflow Example

**Scenario:** Triage 50 security findings from a recent scan

**Traditional Workflow (Manual):**

1. Open `dashboard.html` (2 minutes)
2. Filter by severity (1 minute)
3. Click each finding to read details (30 seconds × 15 findings = 7.5 minutes)
4. Search for vulnerability documentation (3 minutes per finding × 15 = 45 minutes)
5. Write fix code (10 minutes per finding × 15 = 150 minutes)
6. Test fixes (5 minutes per finding × 15 = 75 minutes)

#### Total: ~4.5 hours

**AI-Assisted Workflow (MCP):**

1. Open AI assistant (30 seconds)
2. Ask: "Show me CRITICAL findings" (10 seconds)
3. For each finding, ask: "Suggest a fix for finding abc123" (30 seconds × 15 = 7.5 minutes)
4. Review AI-generated fixes (2 minutes per finding × 15 = 30 minutes)
5. Apply fixes with `apply_fix` tool (30 seconds × 15 = 7.5 minutes)
6. Test fixes (5 minutes per finding × 15 = 75 minutes)

#### Total: ~2 hours (56% time savings)

**Additional Benefits:**

- AI explains CWE/OWASP context automatically
- Suggests alternative remediation approaches
- Highlights compliance requirements (PCI DSS, NIST CSF)
- Tracks which findings are fixed vs. false positives

### Integration Best Practices

**1. Always Run Scans First:**

MCP server requires existing scan results. Run `jmo scan` before starting MCP server.

**2. Use Read-Only Mode for Exploration:**

Default read-only mode is safe for exploring findings. Only enable `--enable-fixes` when actively applying remediation.

**3. Verify AI-Generated Fixes:**

Always review AI-suggested code before applying. Use `dry_run=true` to preview changes.

**4. Track Remediation Status:**

Use `mark_resolved` to track which findings are fixed, false positives, or accepted risks. This persists to `results/triage.json` for audit trails.

**5. Scope to Specific Results:**

Use `--results-dir` to point MCP server at specific scan results. Avoid mixing results from different projects.

**6. Monitor MCP Server Logs:**

Use `--log-level DEBUG` to troubleshoot integration issues. Logs show which tools are called and what data is returned.

### Future Enhancements (Roadmap)

- 🚧 **Multi-results aggregation** - Query findings across multiple scans
- 🚧 **Batch fix application** - Apply fixes to multiple findings at once
- 🚧 **Fix validation** - Automatic testing of AI-generated fixes
- 🚧 **Remediation templates** - Pre-built fix patterns for common vulnerabilities
- 🚧 **Historical tracking** - Trend analysis of remediation velocity

### Additional Resources

- **General MCP Setup:** [docs/MCP_SETUP.md](MCP_SETUP.md)
- **GitHub Copilot Integration:** [docs/integrations/GITHUB_COPILOT.md](integrations/GITHUB_COPILOT.md)
- **Claude Code Integration:** [docs/integrations/CLAUDE_CODE.md](integrations/CLAUDE_CODE.md)
- **MCP Protocol Spec:** <https://modelcontextprotocol.io/>
- **CommonFinding Schema:** [docs/schemas/common_finding.v1.json](schemas/common_finding.v1.json)

## Historical Storage (v1.0.0+)

**Track security scans over time for trend analysis, regression detection, and compliance reporting.**

### Historical Storage Overview

The Historical Storage feature stores scan results in a local SQLite database, enabling:

- **Trend Analysis**: Track finding counts over time (critical/high/medium/low)
- **Regression Detection**: Compare current scan with previous runs
- **Compliance Reporting**: Prove security posture improvements over time
- **Dashboard Data Layer**: Future support for time-series visualizations
- **Multi-Branch Tracking**: Compare security across dev/staging/prod branches

**Key Features:**

- 🗄️ **SQLite Database**: Zero-configuration, file-based storage (`.jmo/history.db`)
- 🔍 **Full Finding History**: Stores all CommonFinding v1.2.0 fields with compliance mappings
- 📊 **Automatic Aggregation**: Severity counts updated via database triggers
- 🌲 **Git Integration**: Tracks commit hash, branch, tag, dirty status
- 🔧 **CI/CD Metadata**: Captures CI provider, build ID, environment variables
- 🎯 **Multi-Target Support**: Works across all 6 target types (repos, images, IaC, URLs, GitLab, K8s)

### Historical Storage Quick Start

**Auto-store during scan (recommended):**

```bash
# Store scan results automatically after completion
jmo scan --repo ./myapp --profile balanced --store-history

# Custom database location
jmo scan --repo ./myapp --profile balanced --store-history --history-db ./scans.db
```

**Manual storage after scanning:**

```bash
# Run scan first
jmo scan --repo ./myapp --profile balanced --results-dir ./results

# Store results manually
jmo history store --results-dir ./results --profile balanced

# Specify database path
jmo history store --results-dir ./results --profile balanced --db ./scans.db
```

### Security & Privacy Features (v1.0.0)

The historical storage system includes comprehensive security and privacy controls designed with a **privacy-first, defense-in-depth approach**.

#### Privacy-First Defaults

**By default, JMo does NOT collect hostname or username metadata.** This ensures your personal information stays private without requiring any configuration.

**Default Behavior:**

- ✅ **CI metadata collected** (ci_provider, ci_build_id, ci_run_number) - Non-PII, useful for tracking builds
- ❌ **Hostname NOT collected** - Your machine name stays private
- ❌ **Username NOT collected** - Your OS username stays private

**Opt-In to Metadata Collection:**

If you want to track which machine ran scans (useful for multi-developer teams or debugging), use the `--collect-metadata` flag:

```bash
# Opt-in to hostname/username collection
jmo scan --repo ./myapp --store-history --collect-metadata
```

**When to use `--collect-metadata`:**

- Team environments where you want to track which developer's machine ran the scan
- Debugging scan environment differences (production vs staging builders)
- Compliance requirements to log scan operator identity

**When to skip `--collect-metadata` (default):**

- Personal projects where privacy matters
- Shared CI/CD runners where hostname/username is meaningless
- Any scenario where you don't want PII in the database

**CI Metadata (Always Collected):**

CI metadata is always collected because it's non-PII and critical for tracking build context:

- `ci_provider`: Detected CI system (github-actions, gitlab-ci, jenkins, etc.)
- `ci_build_id`: Build number or job ID
- `ci_run_number`: Run attempt number (for retries)

#### Secret Redaction

**Automatic secret redaction** prevents sensitive data from being stored in the history database.

**How it works:**

- Secret scanners (trufflehog, noseyparker, semgrep-secrets) automatically redact sensitive fields
- Redacted fields: `Raw`, `RawV2`, `snippet`, `lines`
- Non-secret scanners (trivy, semgrep, checkov) retain full raw data
- Redaction is **automatic and always enabled** for secret scanners

**Example:**

```bash
# Trufflehog finding BEFORE storage (in findings.json)
{
  "id": "abc123...",
  "ruleId": "aws-access-key",
  "raw": {
    "Raw": "AKIAIOSFODNN7EXAMPLE",  # Actual secret exposed
    "RawV2": "arn:aws:iam::123456789012:user/example"
  }
}

# AFTER storage in history.db (raw_finding column)
{
  "id": "abc123...",
  "ruleId": "aws-access-key",
  "raw": {
    "Raw": "[REDACTED]",  # Secret removed
    "RawV2": "[REDACTED]"
  }
}
```

**Disable raw finding storage entirely:**

If you want maximum privacy and don't need raw finding data in the history database, use `--no-store-raw-findings`:

```bash
# Don't store ANY raw finding data in history database
jmo scan --repo ./myapp --store-history --no-store-raw-findings
```

**When to use `--no-store-raw-findings`:**

- Compliance requirements prohibit storing any potential secret data
- Database size is a concern (reduces storage by ~40%)
- You only need aggregate statistics (severity counts, trends)

**Database Schema Impact:**

- The `findings.raw_finding` column is **nullable** (was NOT NULL in pre-v1.0.0)
- Redacted secrets show `"[REDACTED]"` placeholder
- `--no-store-raw-findings` stores `NULL` in `raw_finding` column

#### Finding Data Encryption

**Encrypt raw finding data** using Fernet symmetric encryption for defense-in-depth security.

**Setup:**

```bash
# 1. Generate encryption key (32-byte base64-encoded)
export JMO_ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# 2. Run scan with encryption enabled
jmo scan --repo ./myapp --store-history --encrypt-findings

# 3. Key is persisted in environment or CI secrets
echo $JMO_ENCRYPTION_KEY  # Save this securely!
```

**Key Requirements:**

- **Environment variable:** `JMO_ENCRYPTION_KEY` must be set
- **Key format:** Base64-encoded, minimum 32 bytes
- **Key derivation:** SHA-256 hashing ensures proper Fernet key length

**Error if key missing:**

```bash
jmo scan --repo ./myapp --store-history --encrypt-findings
# ERROR: JMO_ENCRYPTION_KEY environment variable not set. Required for --encrypt-findings.
```

**What gets encrypted:**

- Only the `raw_finding` column in the `findings` table
- Metadata (severity, rule_id, file paths, timestamps) remains **unencrypted** for querying
- Encryption uses **Fernet symmetric encryption** (AES-128-CBC with HMAC authentication)

**Decryption on retrieval:**

```bash
# Export JMO_ENCRYPTION_KEY in your shell
export JMO_ENCRYPTION_KEY="your-key-here"

# Findings are automatically decrypted when queried
jmo history query --severity CRITICAL

# JSON export also decrypts findings
jmo history export scan-report.json --scan-id abc123 --include-findings
```

**When to use `--encrypt-findings`:**

- Shared databases (multi-user access, need to protect raw findings)
- Compliance requirements for encryption at rest
- Defense-in-depth strategy (redaction + encryption + file permissions)

**When to skip `--encrypt-findings`:**

- Single-user local databases (file permissions sufficient)
- Performance-critical environments (encryption adds ~10-20ms overhead)
- Key management complexity outweighs benefits

#### File Permissions Hardening

**Automatic file permissions** ensure only the database owner can read/write the history database.

**Default Behavior (Unix/Linux/macOS):**

```bash
# After first scan with --store-history
ls -la .jmo/history.db
# -rw------- 1 user user 2.4M Nov 04 14:30 .jmo/history.db
#  ^^^ Owner-only read/write (0o600)
```

**File Permissions:**

- **Unix/Linux/macOS:** `0o600` (owner read/write, no group/other access)
- **Windows:** NTFS permissions applied (owner full control)
- **Enforcement:** Applied automatically on database creation and connection

**Security Benefits:**

- Prevents other users on shared systems from reading scan results
- Protects against accidental disclosure if database copied
- Complements encryption (defense-in-depth)

**Override (NOT recommended):**

File permissions are enforced automatically and cannot be disabled. If you need to share the database, use proper access controls:

```bash
# BAD: Weakening permissions
chmod 644 .jmo/history.db  # Will be reset to 0o600 on next connection

# GOOD: Export data for sharing
jmo history export shared-report.json --include-findings
chmod 644 shared-report.json  # Share the export, not the database
```

#### Defense-in-Depth Strategy

**Combine all three security layers for maximum protection:**

```bash
# 1. Generate encryption key
export JMO_ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# 2. Run scan with all security flags
jmo scan --repo ./myapp --store-history \
  --encrypt-findings \           # Layer 1: Encrypt raw findings
  --no-store-raw-findings \      # Layer 2: Don't store raw data at all
  # --collect-metadata omitted   # Layer 3: No PII collection (default)

# 3. Verify database permissions
ls -la .jmo/history.db
# -rw------- 1 user user ...    # Layer 4: File permissions
```

**Security Layers:**

1. **Privacy-first defaults:** No PII collection (hostname/username)
2. **Secret redaction:** Automatic for secret scanners
3. **Encryption:** Fernet symmetric encryption for raw findings
4. **File permissions:** Owner-only access (0o600 on Unix)

**Recommended Configurations by Use Case:**

| Use Case | `--collect-metadata` | `--encrypt-findings` | `--no-store-raw-findings` | Rationale |
|----------|---------------------|---------------------|--------------------------|-----------|
| **Personal projects** | ❌ No | ❌ No | ✅ Yes | Maximum privacy, minimal overhead |
| **Team development** | ✅ Yes | ❌ No | ❌ No | Track developers, file permissions sufficient |
| **Shared CI/CD runners** | ❌ No | ✅ Yes | ❌ No | Encrypt sensitive data, no PII |
| **Compliance audits** | ✅ Yes | ✅ Yes | ✅ Yes | Full auditability with maximum security |
| **Enterprise (multi-tenant)** | ✅ Yes | ✅ Yes | ❌ No | Encryption + PII for full context |

#### Environment Variables Reference

| Variable | Purpose | Default | Required For |
|----------|---------|---------|--------------|
| `JMO_ENCRYPTION_KEY` | Fernet encryption key (base64) | Not set | `--encrypt-findings` |
| `JMO_TELEMETRY` | Enable/disable telemetry | `0` (disabled) | Telemetry opt-in |

**Generating encryption keys:**

```bash
# Python (cryptography library)
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# OpenSSL (alternative)
openssl rand -base64 32

# Store in shell profile for persistence
echo "export JMO_ENCRYPTION_KEY='your-key-here'" >> ~/.bashrc
source ~/.bashrc
```

#### CLI Integration Summary

**All security flags work with `jmo scan` and `jmo history store`:**

```bash
# jmo scan (integrated)
jmo scan --repo ./myapp \
  --store-history \
  --collect-metadata \
  --encrypt-findings \
  --no-store-raw-findings

# jmo history store (manual)
jmo history store --results-dir ./results \
  --collect-metadata \
  --encrypt-findings \
  --no-store-raw-findings
```

**Flag Compatibility:**

- ✅ `--encrypt-findings` + `--no-store-raw-findings`: Compatible (encrypts NULL column, no impact)
- ✅ `--collect-metadata` + `--encrypt-findings`: Compatible (metadata unencrypted, findings encrypted)
- ✅ All three flags together: Compatible (maximum security)

### Historical Storage CLI Commands

#### `jmo history store`

**Store scan results in history database.**

```bash
jmo history store --results-dir RESULTS_DIR [OPTIONS]
```

**Options:**

- `--results-dir DIR` - Results directory containing `summaries/findings.json` (REQUIRED)
- `--profile PROFILE` - Profile name (fast/balanced/deep, default: balanced)
- `--commit HASH` - Git commit hash (auto-detected if in Git repo)
- `--branch NAME` - Git branch name (auto-detected if in Git repo)
- `--tag TAG` - Git tag (auto-detected if in Git repo)
- `--db PATH` - Database path (default: `.jmo/history.db`)

**Example:**

```bash
jmo history store --results-dir ./results --profile balanced --branch main
```

#### `jmo history list`

**List stored scans with summary statistics.**

```bash
jmo history list [OPTIONS]
```

**Options:**

- `--branch NAME` - Filter by Git branch
- `--profile PROFILE` - Filter by profile (fast/balanced/deep)
- `--since TIMESTAMP` - Filter by timestamp (Unix epoch or ISO 8601 format)
- `--limit N` - Limit results (default: 50)
- `--json` - Output as JSON instead of table
- `--db PATH` - Database path (default: `.jmo/history.db`)

**Example:**

```bash
# List all scans
jmo history list

# List scans on main branch
jmo history list --branch main

# List last 10 scans in JSON format
jmo history list --limit 10 --json

# List scans since yesterday (Unix timestamp)
jmo history list --since 1730592000
```

**Sample Output:**

```text
+-------------+---------------------+----------+-----------+------------+------------+--------+----------------+
| Scan ID     | Timestamp           | Branch   | Profile   |   Findings |   Critical |   High | Duration (s)   |
+=============+=====================+==========+===========+============+============+========+================+
| a1b2c3d4... | 2025-11-02 14:30:15 | main     | balanced  |         42 |          3 |     12 | 245.2          |
| e5f6g7h8... | 2025-11-01 09:15:42 | main     | balanced  |         38 |          2 |     10 | 238.7          |
| i9j0k1l2... | 2025-10-31 16:20:03 | dev      | fast      |         15 |          0 |      5 | 89.3           |
+-------------+---------------------+----------+-----------+------------+------------+--------+----------------+
```

#### `jmo history show`

**Show detailed information for a specific scan.**

```bash
jmo history show SCAN_ID [OPTIONS]
```

**Arguments:**

- `SCAN_ID` - Full or partial UUID (e.g., `a1b2c3d4` or full `a1b2c3d4-...`)

**Options:**

- `--json` - Output as JSON
- `--db PATH` - Database path (default: `.jmo/history.db`)

**Example:**

```bash
# Show scan details (accepts partial UUID)
jmo history show a1b2c3d4

# Full output in JSON
jmo history show a1b2c3d4-5e6f-7890-abcd-1234567890ab --json
```

**Sample Output:**

```text
Scan ID:       a1b2c3d4-5e6f-7890-abcd-1234567890ab
Timestamp:     2025-11-02 14:30:15 (1730559015)
Profile:       balanced
Branch:        main
Commit:        abc1234567890def
Tag:           v1.2.3
Dirty:         No

Targets:       myapp, backend-api
Target Type:   repos
Tools:         trivy, semgrep, trufflehog, checkov

Findings:      42 total
  - CRITICAL:  3
  - HIGH:      12
  - MEDIUM:    18
  - LOW:       9
  - INFO:      0

Metadata:
  - Hostname:  builder-01
  - Username:  ci-user
  - CI Provider: github-actions
  - Build ID:  67890
  - Duration:  245.2 seconds
```

#### `jmo history compare`

**Compare two historical scans from the SQLite database.**

```bash
jmo history compare SCAN_ID_1 SCAN_ID_2 [OPTIONS]
```

**Arguments:**

- `SCAN_ID_1` - First scan ID (typically baseline or older scan)
- `SCAN_ID_2` - Second scan ID (typically current or newer scan)

**Options:**

- `--severity LEVEL` - Filter by severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- `--only {new,fixed,modified}` - Show only specific change types
- `--format {json,md,html}` - Output format (default: console)
- `--db PATH` - Database path (default: `.jmo/history.db`)

**Use Cases:**

- Compare baseline scan vs current scan
- Track remediation progress over time
- Detect security regressions

**Example:**

```bash
# List available scans
jmo history list

# Compare two scans
jmo history compare abc123 def456

# Show only new HIGH/CRITICAL findings
jmo history compare abc123 def456 --severity HIGH CRITICAL --only new

# Generate HTML report
jmo history compare abc123 def456 --format html > comparison.html
```

**See Also:**

- `jmo diff` - Compare result directories
- `jmo trends compare` - Compare against baseline with statistics

#### `jmo history query`

**Query findings across stored scans.**

```bash
jmo history query [OPTIONS]
```

**Options:**

- `--scan-id ID` - Filter by specific scan (full or partial UUID)
- `--severity LEVEL` - Filter by severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- `--rule-id ID` - Filter by rule ID (e.g., CVE-2024-1234, CWE-79)
- `--path PATTERN` - Filter by file path pattern (supports wildcards)
- `--limit N` - Limit results (default: 100)
- `--json` - Output as JSON
- `--db PATH` - Database path (default: `.jmo/history.db`)

**Example:**

```bash
# All critical findings
jmo history query --severity CRITICAL

# Findings in specific file
jmo history query --path "src/auth/*.py"

# Findings for specific rule
jmo history query --rule-id CVE-2024-9999

# Combined filters
jmo history query --severity HIGH --path "src/*" --limit 50
```

#### `jmo history prune`

**Remove old scans from history database.**

```bash
jmo history prune [OPTIONS]
```

**Options:**

- `--older-than SECONDS` - Delete scans older than N seconds
- `--keep-scans N` - Keep only the N most recent scans
- `--dry-run` - Show what would be deleted without deleting
- `--db PATH` - Database path (default: `.jmo/history.db`)

**Example:**

```bash
# Delete scans older than 90 days (7776000 seconds)
jmo history prune --older-than 7776000

# Keep only last 100 scans
jmo history prune --keep-scans 100

# Preview what would be deleted
jmo history prune --older-than 2592000 --dry-run
```

#### `jmo history export`

**Export scan history to JSON file.**

```bash
jmo history export OUTPUT_FILE [OPTIONS]
```

**Arguments:**

- `OUTPUT_FILE` - Path to output JSON file

**Options:**

- `--scan-id ID` - Export specific scan only
- `--include-findings` - Include full finding details (default: metadata only)
- `--db PATH` - Database path (default: `.jmo/history.db`)

**Example:**

```bash
# Export all scan metadata
jmo history export scans.json

# Export specific scan with findings
jmo history export scan-a1b2c3d4.json --scan-id a1b2c3d4 --include-findings
```

#### `jmo history stats`

**Show database statistics and trends.**

```bash
jmo history stats [OPTIONS]
```

**Options:**

- `--db PATH` - Database path (default: `.jmo/history.db`)

**Example:**

```bash
jmo history stats
```

**Sample Output:**

```text
Database: .jmo/history.db
Size:     2.4 MB
────────────────────────────────────────────────────────────
Scans:            127
Findings:         3,842
Date Range:       2024-08-15 to 2025-11-02

Scans by Profile:
  balanced      89 scans
  fast          28 scans
  deep          10 scans

Findings by Severity:
  CRITICAL        42  (1.1%)
  HIGH           385  (10.0%)
  MEDIUM         892  (23.2%)
  LOW          1,823  (47.4%)
  INFO           700  (18.2%)

Top Tools:
  trivy                   1,245 findings
  semgrep                   982 findings
  trufflehog                615 findings
  checkov                   412 findings
```

#### `jmo history vacuum`

**Optimize the SQLite history database by reclaiming unused space and rebuilding indexes.**

```bash
jmo history vacuum [OPTIONS]
```

**Options:**

- `--db PATH` - Database path (default: `.jmo/history.db`)

**Description:**

Optimize the SQLite history database by:

- Reclaiming unused space
- Rebuilding indexes
- Improving query performance

**Use Cases:**

- After pruning old scans (`jmo history prune`)
- Database growing too large
- Query performance degradation
- Scheduled maintenance

**Example:**

```bash
# Vacuum database
jmo history vacuum

# Typical output:
# ✅ Database vacuumed successfully
# 📊 Space reclaimed: 15.2 MB → 8.4 MB (45% reduction)
# ⚡ Query performance improved
```

**See Also:**

- `jmo history prune` - Remove old scans
- `jmo history verify` - Check database integrity

#### `jmo history verify`

**Verify SQLite history database integrity.**

```bash
jmo history verify [OPTIONS]
```

**Options:**

- `--db PATH` - Database path (default: `.jmo/history.db`)

**Description:**

Verify SQLite history database integrity by:

- Checking for corruption
- Validating foreign key constraints
- Ensuring schema consistency
- Testing read/write operations

**Use Cases:**

- Troubleshooting database errors
- Post-upgrade verification
- Scheduled health checks
- Before database backup

**Example:**

```bash
# Verify database integrity
jmo history verify

# Successful output:
# ✅ Database integrity check passed
# ✅ Foreign key constraints valid
# ✅ Schema version: 1.0.0
# ✅ Read/write test successful

# Failed output (if corrupted):
# ❌ Database corruption detected
# 💡 Recommendation: Restore from backup or reinitialize
```

**See Also:**

- `jmo history vacuum` - Optimize database
- Troubleshooting - SQLite issues

### Database Schema

The history database uses SQLite with the following schema:

**Tables:**

- `scans` - Scan metadata (timestamp, profile, branch, tools, severity counts, CI metadata)
- `findings` - Individual findings (fingerprint, severity, rule, location, message, full CommonFinding JSON)
- `compliance_mappings` - Framework mappings (OWASP, CWE, CIS, NIST, PCI-DSS, MITRE ATT&CK)
- `schema_version` - Database schema version for migrations

**Key Features:**

- **Foreign Key Constraints**: CASCADE deletion (deleting scan removes findings)
- **Automatic Triggers**: Severity counts auto-updated on INSERT/UPDATE/DELETE
- **Indices**: Optimized for common queries (timestamp DESC, branch, severity, rule_id)
- **Views**: `latest_scan_by_branch`, `finding_history` for quick queries
- **WAL Mode**: Write-Ahead Logging for concurrency and crash resilience

**Schema Changes in v1.0.0 (Security & Privacy):**

- **`findings.raw_finding` column**: Changed from `NOT NULL` to **nullable** to support `--no-store-raw-findings` flag
- **`scans.hostname` column**: Changed from always populated to **NULL by default** (requires `--collect-metadata` opt-in)
- **`scans.username` column**: Changed from always populated to **NULL by default** (requires `--collect-metadata` opt-in)
- **Encryption support**: `raw_finding` column can store encrypted data (Fernet format) when `--encrypt-findings` used
- **File permissions**: Database file automatically set to `0o600` (owner-only) on Unix systems

**Database Location:**

- Default: `.jmo/history.db` (relative to working directory)
- Custom: Use `--db PATH` or `--history-db PATH` flags
- CI/CD: Recommended `.jmo/` directory (gitignored by default)
- **Security:** File permissions automatically enforced (0o600 on Unix)

### Workflow Examples

#### Daily Development Workflow

```bash
# Morning: Baseline scan
jmo scan --repo ./myapp --profile balanced --store-history --branch dev

# Afternoon: After changes
jmo scan --repo ./myapp --profile balanced --store-history --branch dev

# Compare with previous scan
jmo history list --branch dev --limit 2
```

#### Pre-Release Compliance Workflow

```bash
# Run comprehensive scan before release
jmo scan --repo ./myapp --profile deep --store-history --tag v1.2.3

# Generate compliance report
jmo history query --severity CRITICAL --json > critical-findings.json

# Verify no critical findings
if [ $(jq '.findings | length' critical-findings.json) -gt 0 ]; then
  echo "FAIL: Critical findings detected"
  exit 1
fi
```

#### Multi-Branch Comparison

```bash
# Scan production branch
jmo scan --repo ./myapp --profile balanced --store-history --branch main

# Scan staging branch
jmo scan --repo ./myapp --profile balanced --store-history --branch staging

# Compare results
jmo history list --branch main --limit 1
jmo history list --branch staging --limit 1
```

#### Historical Trend Analysis

```bash
# Weekly scans stored over 3 months
jmo scan --repo ./myapp --profile balanced --store-history

# View trends
jmo history list --branch main --limit 12  # Last 12 scans

# Export for external analysis
jmo history export --include-findings monthly-report.json
```

### CI/CD Integration

**GitHub Actions:**

```yaml
- name: Run security scan with history
  run: |
    jmo scan --repo . --profile balanced --store-history

    # Upload database as artifact for trend tracking
    tar -czf history-db.tar.gz .jmo/history.db

- name: Upload history database
  uses: actions/upload-artifact@v4
  with:
    name: scan-history
    path: history-db.tar.gz
    retention-days: 90
```

**GitLab CI:**

```yaml
security_scan:
  script:
    - jmo scan --repo . --profile balanced --store-history --db scans.db
    - jmo history stats --db scans.db
  artifacts:
    paths:
      - scans.db
    expire_in: 3 months
```

### Best Practices

1. **Use `--store-history` flag** for automatic storage (no manual `history store` needed)
2. **Consistent profiles** - Use same profile for trend comparisons (balanced vs balanced)
3. **Regular pruning** - Run `jmo history prune` monthly to limit database size
4. **Git integration** - Run scans in Git repos for automatic branch/commit tracking
5. **CI artifact storage** - Upload `.jmo/history.db` as CI artifact for persistence
6. **Database backups** - Back up `.jmo/history.db` before major schema changes

### Performance Benchmarks

**Validated:** November 2025 (v1.0.0)
**Test Environment:** Linux (WSL2), Python 3.11, SQLite 3.x

The historical storage database is **production-ready** with performance exceeding all targets by 9-117x:

| Operation | Volume | Performance | Target | Status |
|-----------|--------|-------------|--------|--------|
| Store findings | 1,000 findings | **0.017s** | <2s | ✅ **117x faster** |
| Query scans | 10,000 scans | **0.052s (52ms)** | <500ms | ✅ **9.6x faster** |
| Batch insert | 10,000 findings | **0.151s** | <5s | ✅ **33x faster** |
| Recent scans query | 100 scans | **<1ms** | N/A | ✅ **Sub-millisecond** |
| Single scan lookup | 1 scan | **<0.1ms** | N/A | ✅ **Near-instant** |

**Scalability Projections:**

- **Small Deployment** (1-10 repos, daily scans): <1 MB database, <1ms queries ✅
- **Medium Deployment** (10-50 repos, multiple scans/day): ~20-50 MB, <10ms queries ✅
- **Large Deployment** (100+ repos, CI/CD integration): ~200-500 MB, <50ms queries ✅
- **Enterprise** (1000+ repos, continuous scanning): ~2-5 GB, <100ms queries ✅

**Supported Scale:** Up to **1 million scans** without modification. For larger deployments, see [Historical Storage Future Enhancements](#historical-storage-future-enhancements) for sharding/archival options.

**Index Usage:** All 5 critical queries use indices (100% coverage verified). No full table scans on common operations.

**Throughput:**

- **Insert:** ~60,000 findings/second (batch operations)
- **Query:** ~190,000 scans/second (list operations)
- **Single lookup:** Near-instant (primary key lookup)

**For detailed performance analysis:** See `dev-only/1.0.0/PHASE5_PERFORMANCE_RESULTS.md` in the repository.

### Troubleshooting Historical Storage

#### Issue: "Database is locked" error

- Cause: Multiple processes writing to database simultaneously
- Fix: Ensure only one scan writes at a time, or use separate database files

#### Issue: "No findings.json found"

- Cause: Trying to store before report phase completes
- Fix: Ensure `jmo report` completes before `jmo history store`, or use `--store-history` flag which handles timing automatically

#### Issue: Database growing too large

- Cause: Hundreds of scans accumulating
- Fix: Run `jmo history prune --keep-scans 100` to retain last 100 scans

#### Issue: Git context not captured

- Cause: Not running scan in Git repository
- Fix: Run scans from Git repo root, or manually specify `--branch` and `--commit`

### Historical Storage Future Enhancements

- 📊 **Time-series dashboard** - Interactive charts showing trends over time (v1.0.0 Feature #9)
- 🔄 **Automated comparisons** - Diff between scans with highlighted regressions (v1.0.0 Feature #3)
- 📈 **Metrics API** - REST API for external monitoring systems (v1.1.0+)
- 🏷️ **Custom tags** - Label scans with custom metadata (environment, team, project) (v1.1.0+)
- 🔔 **Alert thresholds** - Notify when findings exceed baselines (v1.1.0+)
- 📥 **Import command** - `jmo history import` for loading external scan data (v1.1.0+)
- 🔄 **Schema migrations** - Automatic database upgrades for future versions (v1.1.0+)

**For Developers:** The history database API (`scripts/core/history_db.py`) is designed for extensibility. Future features can use:

- `list_scans(branch, since, profile)` - Time-series data for trend analysis
- `get_findings_for_scan(scan_id, severity)` - Finding details for comparisons
- `get_database_stats()` - Aggregate statistics for dashboards

See [scripts/core/history_db.py](../scripts/core/history_db.py) for complete API documentation.

### Advanced History Queries (Phase 7)

#### Python API for custom integrations: React Dashboard, MCP Server, Compliance Reporting

Phase 7 adds 9 specialized query functions to `scripts/core/history_db.py` designed for future integrations with interactive dashboards, AI-powered remediation systems, and compliance reporting tools.

#### React Dashboard Integration

These functions provide optimized, single-query data fetching for interactive web dashboards built with React and Recharts:

**1. `get_dashboard_summary(conn, scan_id)` - Dashboard-Ready Summary**

Single-query summary reducing multiple round-trips:

```python
from scripts.core.history_db import get_connection, get_dashboard_summary

conn = get_connection(".jmo/history.db")
summary = get_dashboard_summary(conn, "abc123")

# Returns:
{
    "scan": {...},  # Full scan metadata
    "severity_counts": {"CRITICAL": 5, "HIGH": 12, "MEDIUM": 18, ...},
    "top_rules": [
        {"rule_id": "CVE-2024-1234", "count": 8, "severity": "HIGH"},
        ...
    ],
    "tools_used": ["trivy", "semgrep", "trufflehog"],
    "findings_by_tool": {"trivy": 45, "semgrep": 32, ...},
    "compliance_coverage": {
        "total_findings": 100,
        "findings_with_compliance": 85,
        "coverage_percentage": 85.0
    }
}
```

**Performance:** ~5-10ms for single scan

**2. `get_timeline_data(conn, branch, days=30)` - Time-Series Trends**

Optimized for Recharts line/area charts showing severity trends:

```python
timeline = get_timeline_data(conn, branch="main", days=30)

# Returns list of daily data points:
[
    {
        "date": "2025-11-01",
        "scan_id": "abc123",
        "CRITICAL": 3,
        "HIGH": 12,
        "MEDIUM": 18,
        "LOW": 25,
        "INFO": 5,
        "total": 63
    },
    ...
]
```

**Performance:** 30 days: ~10-20ms, 90 days: ~20-40ms

**3. `get_finding_details_batch(conn, fingerprints)` - Lazy Loading**

Batch fetch finding details for drill-down views:

```python
# User clicks on "12 HIGH findings" in dashboard
fingerprints = ["abc123", "def456", "ghi789", ...]
findings = get_finding_details_batch(conn, fingerprints)

# Returns list of full CommonFinding objects
```

**Performance:** 100 findings: ~10-20ms, 1000 findings: ~50-100ms

**4. `search_findings(conn, query, filters=None)` - Full-Text Search**

Search across findings with filters:

```python
# Search for SQL injection findings
results = search_findings(
    conn,
    query="SQL injection",
    filters={
        "severity": "HIGH",
        "branch": "main",
        "date_range": ("2025-11-01", "2025-11-30"),
        "limit": 50
    }
)
```

**Performance:** Simple query: ~5-10ms, With filters: ~10-20ms

#### MCP Server Integration

These functions provide AI-ready data formats for Model Context Protocol servers enabling Claude to suggest remediation strategies:

**5. `get_finding_context(conn, fingerprint)` - Full Context for AI Remediation**

```python
from scripts.core.history_db import get_finding_context

context = get_finding_context(conn, "abc123")

# Returns:
{
    "finding": {...},  # Current finding
    "history": [...],  # Same finding in past scans (up to 10)
    "similar_findings": [...],  # Related findings (up to 5)
    "remediation_history": [...],  # If fixed before, when/how?
    "compliance_impact": {
        "owasp": ["A03:2021"],
        "cwe": [{"id": "CWE-89", "rank": 3}],
        ...
    }
}
```

**Use Case:** AI assistant provides context-aware remediation:

```text
User: "How do I fix finding abc123?"

Claude (using MCP Server):
- "This SQL injection (CWE-89) has appeared 3 times in past 60 days"
- "Previous fix: Use parameterized queries (resolved 2024-10-15)"
- "Compliance impact: OWASP A03:2021, PCI DSS 6.5.1"
- "Suggested fix: [code snippet]"
```

**Performance:** ~10-30ms

**6. `get_scan_diff_for_ai(conn, scan_id_1, scan_id_2)` - AI-Optimized Diff**

```python
diff = get_scan_diff_for_ai(conn, "scan1", "scan2")

# Returns:
{
    "new_findings": [...],  # With priority scoring (1-10)
    "resolved_findings": [...],  # With "likely_fix" heuristics
    "unchanged_findings_count": 42,
    "priority_sorted": True  # Sorted by priority DESC
}

# Priority scoring formula:
# - CRITICAL: base 9-10
# - HIGH: base 7-8
# - + compliance frameworks (1-2 points)
# - + recent recurrence (1 point)
```

**Use Case:** AI prioritizes remediation tasks:

```text
Claude: "Top 3 priorities from this diff:
1. [Priority 10] CVE-2024-9999 (CRITICAL, PCI DSS, CIS)
2. [Priority 9] SQL injection in auth.py (HIGH, OWASP A03)
3. [Priority 8] Hardcoded AWS key (HIGH, recurring 3x)"
```

**Performance:** ~20-50ms

**7. `get_recurring_findings(conn, branch, min_occurrences=3)` - Whack-a-Mole Detection**

Identifies findings that keep reappearing (systemic issues):

```python
recurring = get_recurring_findings(conn, branch="main", min_occurrences=3)

# Returns:
[
    {
        "fingerprint": "abc123",
        "rule_id": "hardcoded-secret",
        "occurrence_count": 5,
        "first_seen": "2025-09-01 10:30:15",
        "last_seen": "2025-11-01 14:20:03",
        "avg_days_between_fixes": 12.5,
        "finding": {...}  # Full CommonFinding
    },
    ...
]
```

**Use Case:** AI suggests process improvements:

```text
Claude: "Warning: 'hardcoded-secret' has recurred 5 times (avg 12.5 days between fixes).
This indicates a systemic issue. Consider:
1. Pre-commit hooks (detect before push)
2. Developer training on secrets management
3. Secrets scanning in CI/CD pipeline"
```

**Performance:** 100 scans: ~50-100ms

#### Compliance Reporting

These functions enable framework-specific compliance dashboards and trend analysis:

**8. `get_compliance_summary(conn, scan_id, framework="all")` - Multi-Framework Summary**

```python
summary = get_compliance_summary(conn, "abc123", framework="all")

# Returns:
{
    "framework_summaries": {
        "owasp_top10_2021": {
            "A01:2021": {"count": 5, "severities": {"HIGH": 3, "MEDIUM": 2}},
            "A02:2021": {"count": 8, "severities": {"CRITICAL": 2, "HIGH": 6}},
            ...
        },
        "cwe_top25_2024": {
            "CWE-79": {"count": 12, "rank": 1, "severities": {...}},
            ...
        },
        "cis_controls_v8_1": {...},
        "nist_csf_2_0": {...},
        "pci_dss_4_0": {...},
        "mitre_attack": {...}
    },
    "coverage_stats": {
        "total_findings": 100,
        "findings_with_compliance": 85,
        "coverage_percentage": 85.0,
        "by_framework": {
            "owasp": 72,
            "cwe": 68,
            "cis": 45,
            "nist": 52,
            "pci": 38,
            "mitre": 15
        }
    }
}
```

**Single-framework query:**

```python
# OWASP Top 10 only
owasp_summary = get_compliance_summary(conn, "abc123", framework="owasp")
```

**Performance:** Single framework: ~10-20ms, All frameworks: ~50-100ms

**9. `get_compliance_trend(conn, branch, framework, days=30)` - Improvement Tracking**

Track compliance improvements over time:

```python
trend = get_compliance_trend(conn, branch="main", framework="owasp", days=30)

# Returns:
{
    "trend": "improving",  # or "degrading", "stable", "insufficient_data"
    "data_points": [
        {
            "scan_id": "abc123",
            "timestamp": "2025-11-01 10:30:15",
            "framework_findings": 15,
            "categories": {
                "A01:2021": 2,
                "A02:2021": 5,
                ...
            }
        },
        ...
    ],
    "insights": [
        "OWASP findings reduced by 40% over 30 days (25 → 15)",
        "A02:2021 (Cryptographic Failures) improved 60% (10 → 4)",
        "A03:2021 (Injection) stable at 3 findings"
    ],
    "summary_stats": {
        "oldest_count": 25,
        "newest_count": 15,
        "reduction_percentage": 40.0,
        "avg_findings_per_scan": 18.5
    }
}
```

**Use Case:** Compliance dashboard showing progress:

```text
OWASP Top 10 Compliance (Last 30 Days)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Status: ✅ Improving (40% reduction)

Key Improvements:
  • A02:2021 (Cryptographic Failures): 60% reduction
  • A06:2021 (Vulnerable Components): 30% reduction

Stable Issues:
  • A03:2021 (Injection): 3 findings (no change)
```

**Performance:** 30 days: ~20-50ms, 90 days: ~50-100ms

#### Performance Summary

All Phase 7 functions target <100ms response times:

| Function | Typical Data | Performance | Target |
|----------|--------------|-------------|--------|
| `get_dashboard_summary` | 1 scan | 5-10ms | <50ms |
| `get_timeline_data` | 30 days | 10-20ms | <50ms |
| `get_finding_details_batch` | 100 findings | 10-20ms | <100ms |
| `search_findings` | Simple query | 5-10ms | <50ms |
| `get_finding_context` | 1 finding + history | 10-30ms | <100ms |
| `get_scan_diff_for_ai` | 2 scans | 20-50ms | <100ms |
| `get_recurring_findings` | 100 scans | 50-100ms | <100ms |
| `get_compliance_summary` (single) | 1 scan | 10-20ms | <50ms |
| `get_compliance_summary` (all) | 1 scan | 50-100ms | <100ms |
| `get_compliance_trend` | 30 days | 20-50ms | <100ms |

**All functions use indices for optimal performance. No full table scans on common operations.**

#### Example Use Cases

##### Use Case 1: React Dashboard Component

```javascript
// Dashboard.jsx
import React, { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, Tooltip } from 'recharts';

function SecurityDashboard({ scanId }) {
  const [summary, setSummary] = useState(null);
  const [timeline, setTimeline] = useState([]);

  useEffect(() => {
    // Fetch data from Python backend API
    fetch(`/api/history/dashboard/${scanId}`)
      .then(res => res.json())
      .then(data => setSummary(data));

    fetch(`/api/history/timeline?branch=main&days=30`)
      .then(res => res.json())
      .then(data => setTimeline(data));
  }, [scanId]);

  return (
    <div>
      <h2>Security Scan Summary</h2>
      <div>
        <span>CRITICAL: {summary?.severity_counts.CRITICAL}</span>
        <span>HIGH: {summary?.severity_counts.HIGH}</span>
      </div>

      <LineChart width={800} height={400} data={timeline}>
        <XAxis dataKey="date" />
        <YAxis />
        <Line type="monotone" dataKey="CRITICAL" stroke="#dc2626" />
        <Line type="monotone" dataKey="HIGH" stroke="#ea580c" />
        <Tooltip />
      </LineChart>
    </div>
  );
}
```

**Backend API endpoint (Flask example):**

```python
from flask import Flask, jsonify
from scripts.core.history_db import get_connection, get_dashboard_summary, get_timeline_data

app = Flask(__name__)

@app.route('/api/history/dashboard/<scan_id>')
def dashboard_summary(scan_id):
    conn = get_connection(".jmo/history.db")
    summary = get_dashboard_summary(conn, scan_id)
    return jsonify(summary)

@app.route('/api/history/timeline')
def timeline(branch, days=30):
    conn = get_connection(".jmo/history.db")
    data = get_timeline_data(conn, branch, days)
    return jsonify(data)
```

##### Use Case 2: MCP Server for Claude Integration

```python
# mcp_server.py
from mcp import Server
from scripts.core.history_db import get_connection, get_finding_context, get_scan_diff_for_ai

server = Server("jmo-security-mcp")

@server.tool("get_finding_remediation")
async def get_remediation(fingerprint: str) -> dict:
    """Provide AI with full context for remediation suggestions."""
    conn = get_connection(".jmo/history.db")
    context = get_finding_context(conn, fingerprint)

    return {
        "finding": context["finding"]["message"],
        "history": f"Seen {len(context['history'])} times before",
        "last_fix": context["remediation_history"][0] if context["remediation_history"] else None,
        "compliance": context["compliance_impact"],
        "suggestion": generate_fix_suggestion(context)  # AI-powered
    }

@server.tool("prioritize_findings")
async def prioritize_findings(scan1: str, scan2: str) -> list:
    """Return prioritized list of new findings for remediation."""
    conn = get_connection(".jmo/history.db")
    diff = get_scan_diff_for_ai(conn, scan1, scan2)

    return [
        {
            "priority": f["priority"],
            "rule_id": f["rule_id"],
            "path": f["location"]["path"],
            "message": f["message"]
        }
        for f in diff["new_findings"][:10]  # Top 10
    ]
```

##### Use Case 3: Compliance Reporting Dashboard

```python
# compliance_report.py
from scripts.core.history_db import get_connection, get_compliance_summary, get_compliance_trend

def generate_compliance_report(scan_id, output_format="html"):
    conn = get_connection(".jmo/history.db")

    # Get current compliance status
    summary = get_compliance_summary(conn, scan_id, framework="all")

    # Get trends for each framework
    frameworks = ["owasp", "cwe", "cis", "nist", "pci", "mitre"]
    trends = {}
    for framework in frameworks:
        trends[framework] = get_compliance_trend(conn, "main", framework, days=90)

    # Generate HTML report
    html = f"""
    <h1>Compliance Report</h1>
    <h2>Current Status</h2>
    <ul>
        <li>OWASP Top 10: {summary['framework_summaries']['owasp_top10_2021']}</li>
        <li>CWE Top 25: {summary['framework_summaries']['cwe_top25_2024']}</li>
    </ul>

    <h2>90-Day Trends</h2>
    <ul>
        <li>OWASP: {trends['owasp']['trend']} ({trends['owasp']['insights'][0]})</li>
        <li>CWE: {trends['cwe']['trend']} ({trends['cwe']['insights'][0]})</li>
    </ul>
    """

    return html
```

#### Future Integration Examples

These functions are designed for extensibility:

1. **Grafana Dashboards**: Query functions provide Prometheus-style metrics
2. **Slack/Teams Bots**: Real-time compliance trend alerts
3. **Jupyter Notebooks**: Data science analysis of security posture
4. **GitHub Actions**: Automated compliance gate checks
5. **Security Information and Event Management (SIEM)**: Export findings to Splunk/ELK

See [scripts/core/history_db.py](../scripts/core/history_db.py) (lines 1790-3008) for complete function signatures and implementation details.

## Trend Analysis (v1.0.0+)

**Analyze security scan trends over time using statistical methods, detect regressions, and track developer remediation efforts.**

### Trend Analysis Overview

The Trend Analysis feature provides powerful tools to understand how your security posture evolves over time. Built on the Historical Storage foundation, it uses the Mann-Kendall statistical test and other advanced analytics to identify meaningful trends, detect regressions, and measure security improvements.

**Key Features:**

- 📈 **Statistical Trend Detection**: Mann-Kendall test (p < 0.05) for statistically significant trends
- 🚨 **Regression Detection**: Identify new CRITICAL/HIGH findings between scans
- 🎯 **Security Score**: Quantify security posture (0-100 scale) with letter grades (A-F)
- 📊 **Automated Insights**: AI-powered recommendations based on trend patterns
- 👤 **Developer Attribution**: Track who fixed what using git blame integration
- 📤 **Multiple Export Formats**: CSV, Prometheus, Grafana, Dashboard JSON
- 🖥️ **Rich Output Formats**: Terminal tables, JSON, interactive HTML reports

**What Makes It Unique:**

Unlike simple diff tools, Trend Analysis uses rigorous statistical methods to distinguish real trends from noise. The Mann-Kendall test ensures trends are statistically significant (p < 0.05), not just random fluctuations.

### Trend Analysis Quick Start

**Prerequisites:**

Trend analysis requires at least 2 scans stored in history database:

```bash
# First scan (baseline)
jmo scan --repo ./myapp --profile balanced --store-history

# Make changes, then run second scan
jmo scan --repo ./myapp --profile balanced --store-history

# Analyze trends
jmo trends analyze
```

**Basic Workflow:**

```bash
# 1. Run initial baseline scan
jmo scan --repo ./myapp --profile balanced --store-history

# 2. Run periodic scans (daily/weekly)
jmo scan --repo ./myapp --profile balanced --store-history

# 3. View trend analysis
jmo trends analyze

# 4. Check for regressions
jmo trends regressions

# 5. View security score
jmo trends score
```

### Trend Analysis CLI Commands

#### `jmo trends analyze`

**Perform comprehensive trend analysis across stored scans.**

```bash
jmo trends analyze [OPTIONS]
```

**Options:**

- `--branch NAME` - Filter scans by Git branch (default: all branches)
- `--since TIMESTAMP` - Analyze scans since timestamp (Unix epoch or ISO 8601)
- `--scans N` - Analyze last N scans (default: all scans)
- `--min-scans N` - Minimum scans required for analysis (default: 2)
- `--format FORMAT` - Output format: `terminal` (default), `json`, `html`
- `--output FILE` - Write output to file instead of stdout
- `--db PATH` - Database path (default: `.jmo/history.db`)
- `--export FORMAT` - Export data: `csv`, `prometheus`, `grafana`, `dashboard`
- `--export-file FILE` - Export file path (required with `--export`)

**Examples:**

```bash
# Basic analysis (all scans, all branches)
jmo trends analyze

# Analyze last 10 scans on main branch
jmo trends analyze --branch main --scans 10

# Analyze scans from last 30 days
jmo trends analyze --since "30 days ago"

# Generate HTML report
jmo trends analyze --format html --output trend-report.html

# Export to Prometheus metrics
jmo trends analyze --export prometheus --export-file metrics.prom

# Export to Grafana JSON dashboard
jmo trends analyze --export grafana --export-file dashboard.json
```

**Sample Terminal Output:**

```text
╔══════════════════════════════════════════════════════════════════╗
║                     Trend Analysis Report                         ║
╚══════════════════════════════════════════════════════════════════╝

Analysis Period: 2025-10-01 to 2025-11-05 (35 days)
Scans Analyzed: 12
Branch: main
Profile: balanced

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Severity Trends (Mann-Kendall Test, α=0.05)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Severity    Trend        Tau      p-value   Significance
  ─────────────────────────────────────────────────────────────────
  CRITICAL    improving   -0.682    0.001     ✓ significant
  HIGH        stable      -0.242    0.123     ✗ not significant
  MEDIUM      improving   -0.515    0.012     ✓ significant
  LOW         stable       0.091    0.587     ✗ not significant
  INFO        stable      -0.030    0.861     ✗ not significant

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Top Rules (Last 30 Days)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Rule ID              Severity    Count    % of Total
  ─────────────────────────────────────────────────────────────────
  CVE-2024-1234        CRITICAL       18        14.5%
  CWE-89               HIGH           12         9.7%
  CWE-79               HIGH           10         8.1%
  CVE-2024-5678        HIGH            8         6.5%

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Security Score
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Current Score: 78 (C)
  Previous Score: 65 (D)
  Change: +13 points (↑ improving)

  Grade Distribution:
    A (90-100):  2 scans
    B (80-89):   1 scan
    C (70-79):   4 scans
    D (60-69):   3 scans
    F (<60):     2 scans

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Automated Insights
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ✓ CRITICAL findings decreasing (-68% over 12 scans)
  ✓ Security score improving (+20% in last 30 days)
  ⚠ HIGH findings still elevated (>10 per scan)
  ⚠ 3 regressions detected in last scan (scan_abc123)
  ℹ Most common issue: CVE-2024-1234 (upgrade dependency X to v2.0+)
```

#### `jmo trends show`

**Show scan context window (N scans before/after a specific scan).**

```bash
jmo trends show [SCAN_ID] [OPTIONS]
```

**Arguments:**

- `SCAN_ID` - Full or partial UUID (optional, defaults to latest scan)

**Options:**

- `--window N` - Number of scans before/after to show (default: 5)
- `--branch NAME` - Filter scans by branch
- `--format FORMAT` - Output format: `terminal` (default), `json`
- `--db PATH` - Database path (default: `.jmo/history.db`)

**Examples:**

```bash
# Show context for latest scan (5 before, 5 after)
jmo trends show

# Show context for specific scan
jmo trends show abc123 --window 3

# Show last 10 scans on main branch
jmo trends show --branch main --window 10
```

#### `jmo trends regressions`

**Detect regressions (new CRITICAL/HIGH findings) between scans.**

```bash
jmo trends regressions [OPTIONS]
```

**Options:**

- `--scan-id ID` - Compare specific scan to previous (default: latest scan)
- `--branch NAME` - Filter by branch
- `--severity LEVEL` - Show regressions for severity level (default: CRITICAL,HIGH)
- `--format FORMAT` - Output format: `terminal` (default), `json`
- `--db PATH` - Database path (default: `.jmo/history.db`)

**Examples:**

```bash
# Detect regressions in latest scan
jmo trends regressions

# Check specific scan for regressions
jmo trends regressions --scan-id abc123

# Show CRITICAL regressions only
jmo trends regressions --severity CRITICAL

# Check regressions on staging branch
jmo trends regressions --branch staging
```

#### `jmo trends score`

**Calculate and display security score (0-100) with letter grades.**

```bash
jmo trends score [OPTIONS]
```

**Options:**

- `--branch NAME` - Filter by branch
- `--scans N` - Show last N scans (default: all)
- `--format FORMAT` - Output format: `terminal` (default), `json`
- `--db PATH` - Database path (default: `.jmo/history.db`)

**Score Calculation:**

```text
Score = 100 - (critical_count × 10) - (high_count × 3) - (medium_count × 1)
Score = max(0, Score)  # Floor at 0

Grades:
  A: 90-100
  B: 80-89
  C: 70-79
  D: 60-69
  F: <60
```

**Examples:**

```bash
# Show current security score
jmo trends score

# Show score history for last 10 scans
jmo trends score --scans 10

# Score for specific branch
jmo trends score --branch main
```

#### `jmo trends compare`

**Side-by-side comparison of two scans.**

```bash
jmo trends compare SCAN_ID_1 SCAN_ID_2 [OPTIONS]
```

**Arguments:**

- `SCAN_ID_1` - First scan ID (full or partial UUID)
- `SCAN_ID_2` - Second scan ID (full or partial UUID)

**Options:**

- `--format FORMAT` - Output format: `terminal` (default), `json`
- `--db PATH` - Database path (default: `.jmo/history.db`)

**Examples:**

```bash
# Compare two specific scans
jmo trends compare abc123 def456

# Compare latest scan with previous
jmo trends compare latest previous
```

#### `jmo trends insights`

**Generate automated insights and recommendations based on trends.**

```bash
jmo trends insights [OPTIONS]
```

**Options:**

- `--branch NAME` - Filter by branch
- `--scans N` - Analyze last N scans (default: all)
- `--format FORMAT` - Output format: `terminal` (default), `json`
- `--db PATH` - Database path (default: `.jmo/history.db`)

**Examples:**

```bash
# Generate insights for all scans
jmo trends insights

# Insights for last 10 scans on main
jmo trends insights --branch main --scans 10
```

#### `jmo trends explain`

**Explain trend terminology and statistical methods.**

```bash
jmo trends explain [TOPIC]
```

**Available Topics:**

- `mann-kendall` - Mann-Kendall statistical test
- `security-score` - Security score calculation
- `regression` - Regression detection logic
- `trends` - Trend classification (improving/stable/degrading)
- `all` - Show all explanations

**Examples:**

```bash
# Explain Mann-Kendall test
jmo trends explain mann-kendall

# Explain security score formula
jmo trends explain security-score

# Show all explanations
jmo trends explain all
```

#### `jmo trends developers`

**Track developer remediation efforts using git blame attribution.**

```bash
jmo trends developers [OPTIONS]
```

**Options:**

- `--scan-id ID` - Analyze specific scan (default: latest)
- `--branch NAME` - Filter by branch
- `--format FORMAT` - Output format: `terminal` (default), `json`
- `--team-map FILE` - JSON file mapping developers to teams
- `--velocity` - Show developer velocity metrics
- `--db PATH` - Database path (default: `.jmo/history.db`)

**Examples:**

```bash
# Show developer attribution for latest scan
jmo trends developers

# Show attribution with team aggregation
jmo trends developers --team-map teams.json

# Show developer velocity (fixes per week)
jmo trends developers --velocity

# Analyze specific scan
jmo trends developers --scan-id abc123
```

**Team Mapping File (`teams.json`):**

```json
{
  "Frontend Team": ["alice@example.com", "bob@example.com"],
  "Backend Team": ["charlie@example.com", "dave@example.com"],
  "DevOps Team": ["eve@example.com"]
}
```

### Export Formats

Trend analysis supports 4 export formats for integration with external systems.

#### CSV Export

**Use case:** Excel, Google Sheets, data analysis

```bash
jmo trends analyze --export csv --export-file trends.csv
```

**CSV Structure:**

```csv
scan_id,timestamp,branch,profile,critical,high,medium,low,info,total,score,grade
abc123,2025-11-05T14:30:15,main,balanced,2,10,20,30,5,67,78,C
def456,2025-11-04T08:45:33,main,balanced,3,12,22,32,8,77,65,D
```

#### Prometheus Export

**Use case:** Monitoring, alerting, Grafana dashboards

```bash
jmo trends analyze --export prometheus --export-file metrics.prom
```

**Prometheus Metrics Format:**

```prometheus
# HELP jmo_scan_findings_total Total findings by severity
# TYPE jmo_scan_findings_total gauge
jmo_scan_findings_total{severity="critical",branch="main",profile="balanced"} 2
jmo_scan_findings_total{severity="high",branch="main",profile="balanced"} 10
jmo_scan_findings_total{severity="medium",branch="main",profile="balanced"} 20

# HELP jmo_security_score Security posture score (0-100)
# TYPE jmo_security_score gauge
jmo_security_score{branch="main",profile="balanced"} 78

# HELP jmo_scan_duration_seconds Scan duration in seconds
# TYPE jmo_scan_duration_seconds gauge
jmo_scan_duration_seconds{branch="main",profile="balanced"} 245.2
```

**Grafana Query Examples:**

```promql
# Show CRITICAL findings over time
jmo_scan_findings_total{severity="critical"}

# Calculate change rate
rate(jmo_scan_findings_total{severity="high"}[7d])

# Security score trend
jmo_security_score{branch="main"}

# Alert on regressions
increase(jmo_scan_findings_total{severity="critical"}[1h]) > 0
```

#### Grafana Dashboard JSON Export

**Use case:** Pre-built Grafana dashboards

```bash
jmo trends analyze --export grafana --export-file dashboard.json
```

**Features:**

- Time-series line charts (severity trends)
- Stat panels (current score, grade)
- Bar charts (findings by tool)
- Heatmap (findings by day of week)
- Alerts configured for regressions

**Import to Grafana:**

1. Navigate to Dashboards → Import
2. Upload `dashboard.json`
3. Configure Prometheus data source
4. Dashboard ready to use

#### Dashboard JSON Export

**Use case:** Custom web dashboards, React apps

```bash
jmo trends analyze --export dashboard --export-file dashboard.json
```

**JSON Structure:**

```json
{
  "summary": {
    "scan_count": 12,
    "date_range": ["2025-10-01", "2025-11-05"],
    "branch": "main",
    "profile": "balanced"
  },
  "current_scan": {
    "scan_id": "abc123",
    "timestamp": "2025-11-05T14:30:15",
    "critical": 2,
    "high": 10,
    "medium": 20,
    "low": 30,
    "info": 5,
    "total": 67,
    "score": 78,
    "grade": "C"
  },
  "trends": {
    "critical": {"trend": "improving", "tau": -0.682, "p_value": 0.001},
    "high": {"trend": "stable", "tau": -0.242, "p_value": 0.123}
  },
  "timeline": [
    {"date": "2025-11-01", "critical": 3, "high": 12, "score": 65},
    {"date": "2025-11-05", "critical": 2, "high": 10, "score": 78}
  ],
  "regressions": {
    "new_findings": 3,
    "remediated_findings": 4,
    "details": [...]
  },
  "top_rules": [
    {"rule_id": "CVE-2024-1234", "count": 18, "severity": "CRITICAL"}
  ]
}
```

### Wizard Integration

The interactive wizard includes trend analysis prompts after scans:

```text
╔══════════════════════════════════════════════════════════════════╗
║                   Scan Complete! 🎉                               ║
╚══════════════════════════════════════════════════════════════════╝

Results: ./results/summaries/dashboard.html
Findings: 67 total (2 CRITICAL, 10 HIGH, 20 MEDIUM)

📊 Trend Analysis Available

You have 12 scans in history. Would you like to view trend analysis?

  1) View full trend analysis
  2) Check for regressions
  3) View security score
  4) Skip

Your choice [1-4]: 1

[Launches jmo trends analyze with formatted terminal output]
```

### CI/CD Integration

**GitHub Actions Example:**

```yaml
name: Security Scan with Trends

on:
  push:
    branches: [main, staging]
  schedule:
    - cron: '0 2 * * 1'  # Weekly Monday 2 AM

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Restore history database
        uses: actions/cache@v4
        with:
          path: .jmo/history.db
          key: jmo-history-${{ github.ref_name }}

      - name: Run security scan
        run: |
          jmo scan --repo . --profile balanced --store-history

      - name: Analyze trends
        run: |
          jmo trends analyze --format json --output trends.json
          jmo trends regressions
          jmo trends score

      - name: Export metrics for Grafana
        run: |
          jmo trends analyze --export prometheus --export-file metrics.prom

      - name: Check for critical regressions
        run: |
          # Fail if new CRITICAL findings detected
          if jmo trends regressions --severity CRITICAL | grep -q "new findings"; then
            echo "❌ CRITICAL regressions detected!"
            exit 1
          fi

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: security-trends
          path: |
            trends.json
            metrics.prom
            .jmo/history.db
```

**GitLab CI Example:**

```yaml
security_trends:
  stage: security
  script:
    - jmo scan --repo . --profile balanced --store-history --db scans.db
    - jmo trends analyze --db scans.db --format html --output trends.html
    - jmo trends regressions --db scans.db
    - jmo trends score --db scans.db
    - jmo trends analyze --db scans.db --export grafana --export-file dashboard.json
  artifacts:
    paths:
      - scans.db
      - trends.html
      - dashboard.json
    expire_in: 90 days
  cache:
    key: history-$CI_COMMIT_REF_NAME
    paths:
      - scans.db
```

### Docker Usage

**Volume mounting for history persistence:**

```bash
# Create persistent history directory
mkdir -p $PWD/.jmo

# Run scan with history
docker run --rm \
  -v $PWD:/scan:ro \
  -v $PWD/.jmo:/scan/.jmo \
  jmo-security:latest \
  scan --repo /scan --profile balanced --store-history

# Analyze trends
docker run --rm \
  -v $PWD/.jmo:/scan/.jmo \
  jmo-security:latest \
  trends analyze --db /scan/.jmo/history.db
```

**Docker Compose Example:**

See [docker-compose.trends.yml](../docker-compose.trends.yml) for complete example with volume persistence and multi-stage workflows.

### Best Practices

1. **Regular Scanning** - Run scans at consistent intervals (daily/weekly) for reliable trend detection
2. **Minimum Scans** - Need at least 5-7 scans for statistically meaningful trends
3. **Consistent Profiles** - Use same profile (balanced vs balanced) for trend comparisons
4. **Branch Strategy** - Track trends separately per branch (main, staging, dev)
5. **CI/CD Cache** - Use GitHub Actions cache or GitLab artifacts to persist history database
6. **Export Metrics** - Push Prometheus metrics to monitoring systems for alerting
7. **Regression Gating** - Fail CI if new CRITICAL/HIGH findings detected
8. **Developer Attribution** - Run in Git repos for automatic git blame tracking

### Troubleshooting Trends

#### Issue: "Insufficient scans for analysis"

- **Cause:** Less than 2 scans in history database
- **Fix:** Run at least 2 scans with `--store-history` before analyzing trends

```bash
# Solution
jmo scan --repo ./myapp --profile balanced --store-history
# ... make changes ...
jmo scan --repo ./myapp --profile balanced --store-history
jmo trends analyze
```

#### Issue: "No significant trends detected"

- **Cause:** Not enough scans, or findings are genuinely stable
- **Explanation:** Mann-Kendall test requires sufficient data points (5-7+ scans) and consistent patterns to detect trends
- **Fix:** Continue running scans regularly for 2-4 weeks to establish trend patterns

#### Issue: Git blame not working in Docker

- **Cause:** Git history not available in container
- **Fix:** Mount Git directory and ensure `.git` is accessible

```bash
docker run --rm \
  -v $PWD:/scan \
  -v $PWD/.git:/scan/.git:ro \
  jmo-security:latest \
  trends developers
```

#### Issue: Trends show "stable" when findings clearly changed

- **Cause:** Statistical significance threshold (p < 0.05) not met
- **Explanation:** Changes may be real but not statistically significant due to high variance or small sample size
- **Fix:** Accumulate more scans (10-15+) or reduce variance by using consistent scan profiles

#### Issue: Developer attribution showing "unknown"

- **Cause:** Not running in Git repository, or Git history unavailable
- **Fix:**
  - Run scans from Git repo root
  - Ensure `.git` directory exists and is accessible
  - Check Git configuration: `git config user.name` and `git config user.email`

### Statistical Methods Reference

#### Mann-Kendall Trend Test

**What it detects:** Monotonic trends (consistent increase or decrease) in time series data

**Null Hypothesis (H₀):** No trend exists (data is randomly ordered)

**Alternative Hypothesis (H₁):** A trend exists (data has consistent increase or decrease)

**Test Statistic (S):**

```text
S = Σ sgn(xⱼ - xᵢ) for all pairs i < j

where sgn(x) = {
   1  if x > 0
   0  if x = 0
  -1  if x < 0
}
```

**Kendall's Tau (τ):**

```text
τ = S / (n(n-1)/2)

where n = number of data points
```

**Variance (for p-value calculation):**

```text
Var(S) = n(n-1)(2n+5) / 18
```

**Z-statistic:**

```text
Z = {
  (S - 1) / √Var(S)    if S > 0
   0                   if S = 0
  (S + 1) / √Var(S)    if S < 0
}
```

**p-value:** Probability from standard normal distribution

**Decision Rule:**

- If p < 0.05 (α=0.05): Reject H₀, trend is significant
- If p ≥ 0.05: Fail to reject H₀, no significant trend

**Trend Classification:**

```text
if p < 0.05 and τ < -0.3: "improving" (significant decrease)
elif p < 0.05 and τ > 0.3: "degrading" (significant increase)
else: "stable" (no significant trend)
```

**Advantages:**

- Non-parametric (no distribution assumptions)
- Robust to outliers
- Works with non-linear trends
- Handles missing data gracefully

**Limitations:**

- Requires minimum 4-5 data points (we recommend 5-7)
- Assumes independence of observations
- Detects monotonic trends only (not cyclical patterns)

### Future Enhancements

**v1.1.0 Planned Features:**

- 🔔 **Threshold Alerting** - Slack/email notifications when trends degrade
- 📊 **Interactive Web Dashboard** - React-based time-series visualizations
- 🤖 **AI-Powered Insights** - LLM-based remediation suggestions
- 📈 **Predictive Analytics** - Forecast future finding counts using ARIMA models
- 🏷️ **Custom Metrics** - Define custom aggregations and KPIs
- 🔄 **Automated Baselines** - Auto-detect "good" baseline scans for comparison
- 📥 **Import Historical Data** - Import scans from other security tools

## Machine-Readable Diffs (v1.0.0+)

**Compare two security scans to identify new, resolved, and modified findings.**

The `jmo diff` command enables intelligent comparison of scan results using fingerprint-based matching, supporting PR reviews, CI/CD gates, remediation tracking, and trend analysis.

### Key Features

- **Fingerprint Matching**: O(n) performance with stable finding IDs
- **Four Classifications**: NEW, RESOLVED, UNCHANGED, MODIFIED
- **Modification Detection**: Tracks severity upgrades, compliance changes, priority shifts
- **Four Output Formats**: JSON (v1.0.0), Markdown (PR comments), HTML (interactive), SARIF 2.1.0
- **Flexible Filtering**: By severity, tool, category, or combination
- **CI/CD Ready**: GitHub Actions and GitLab CI examples included

### Two Comparison Modes

#### 1. Directory Mode (Primary)

Compare findings from two results directories:

```bash
# Basic comparison
jmo diff baseline-results/ current-results/ --format md --output pr-diff.md

# With filtering
jmo diff baseline/ current/ \
  --format json \
  --severity CRITICAL,HIGH \
  --only new \
  --output critical-findings.json
```

**Use Cases:**

- PR reviews: Compare main branch vs feature branch
- Release validation: Compare previous release vs current
- Sprint tracking: Compare sprint start vs sprint end

#### 2. SQLite Mode (Historical)

Compare two scan IDs from history database:

```bash
# Compare historical scans
jmo diff \
  --scan abc123-baseline \
  --scan def456-current \
  --format md \
  --output diff.md

# Custom database location
jmo diff \
  --scan scan-id-1 \
  --scan scan-id-2 \
  --db /custom/path/history.db \
  --format json
```

**Use Cases:**

- Long-term trend analysis
- Quarterly compliance reporting
- Regression detection across releases

### CLI Reference

```bash
jmo diff [OPTIONS] [BASELINE] [CURRENT]

# Positional Arguments (Directory Mode)
  BASELINE                  # Baseline results directory
  CURRENT                   # Current results directory

# SQLite Mode
  --scan SCAN_ID            # Scan ID (provide twice: baseline, current)
  --db PATH                 # History database path (default: .jmo/history.db)

# Output Options
  --output PATH             # Output file path (extension added by format)
  --format FORMAT           # json|md|html|sarif (can specify multiple)

# Filtering
  --severity SEV [SEV...]   # CRITICAL|HIGH|MEDIUM|LOW|INFO
  --tool TOOL [TOOL...]     # Filter by tool names
  --only CATEGORY           # new|resolved|modified
  --no-modifications        # Skip modification detection (faster)

# Behavior
  --fail-on SEV             # Exit 1 if new findings at severity level
  --quiet                   # Suppress summary output
```

### Output Formats

#### JSON (Machine-Readable)

v1.0.0 schema with metadata wrapper:

```json
{
  "meta": {
    "diff_version": "1.0.0",
    "jmo_version": "1.0.0",
    "timestamp": "2025-11-05T10:30:00Z",
    "baseline": {...},
    "current": {...}
  },
  "statistics": {
    "total_new": 12,
    "total_resolved": 20,
    "total_unchanged": 120,
    "total_modified": 2,
    "net_change": -8,
    "trend": "improving",
    "new_by_severity": {...},
    "resolved_by_severity": {...}
  },
  "findings": {
    "new": [...],
    "resolved": [...],
    "modified": [...]
  }
}
```

**Use Case:** CI/CD automation, programmatic analysis

#### Markdown (PR Comments)

Human-readable format with collapsible details:

```markdown
# 🔍 Security Diff Report

## 📊 Summary

| Metric | Count | Change |
|--------|-------|--------|
| **New Findings** | 12 | 🔴 +12 |
| **Resolved Findings** | 20 | ✅ -20 |
| **Net Change** | -8 | ✅ Improving |

## ⚠️ New Findings (12)

### 🔴 CRITICAL (1)

<details>
<summary><b>SQL Injection in user query handler</b></summary>

**Rule:** `semgrep.sql-injection`
**File:** `src/database.py:127`

**Message:** Unsanitized user input flows into SQL query...

</details>
```

**Use Case:** GitHub/GitLab PR comments, team reviews

#### HTML (Interactive Dashboard)

Self-contained interactive dashboard with:

- Severity filtering
- Search/filter by rule, tool, path
- Side-by-side comparison for modified findings
- Collapsible finding cards
- Dark mode support

**Use Case:** Visual exploration, management reporting

#### SARIF 2.1.0 (Code Scanning)

GitHub/GitLab Code Scanning integration with `baselineState` annotations:

```json
{
  "runs": [{
    "results": [{
      "baselineState": "new",
      "properties": {
        "diff_category": "new",
        "baseline_severity": null,
        "current_severity": "error"
      }
    }]
  }]
}
```

**Use Case:** GitHub Security tab, GitLab SAST dashboard

### Modification Detection

**Enabled by default** - detects 5 types of changes:

1. **Severity Changes**: MEDIUM → HIGH (upgrade/downgrade)
2. **Priority Changes**: EPSS/KEV updates (risk delta)
3. **Compliance Changes**: New framework mappings added
4. **CWE Changes**: CWE classification updates
5. **Message Changes**: Finding description updates

**Example:**

```json
{
  "fingerprint": "abc123...",
  "changes": {
    "severity": ["MEDIUM", "HIGH"],
    "priority": [45.2, 78.9],
    "compliance_frameworks": [
      ["owasp"],
      ["owasp", "pci_dss"]
    ]
  }
}
```

**Disable for performance:**

```bash
jmo diff baseline/ current/ --no-modifications  # 30% faster
```

### CI/CD Integration Examples

#### GitHub Actions (PR Comments)

```yaml
name: Security Diff on PR

on:
  pull_request:
    branches: [main]

jobs:
  security-diff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      # Scan baseline (main branch)
      - name: Checkout main
        run: git checkout main

      - name: Scan main branch
        run: jmo scan --repo . --profile balanced --results-dir baseline-results

      # Scan current PR
      - name: Checkout PR
        run: git checkout ${{ github.event.pull_request.head.sha }}

      - name: Scan PR branch
        run: jmo scan --repo . --profile balanced --results-dir current-results

      # Generate diff
      - name: Generate diff
        run: |
          jmo diff baseline-results/ current-results/ \
            --format md \
            --output pr-diff.md \
            --fail-on HIGH

      # Post PR comment
      - name: Post PR comment
        if: always()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const diff = fs.readFileSync('pr-diff.md', 'utf8');

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: diff
            });
```

**Complete example:** [docs/examples/github-actions-diff.yml](../docs/examples/github-actions-diff.yml)

#### GitLab CI (Merge Request Comments)

```yaml
security-diff:
  stage: test
  script:
    # Scan baseline
    - git checkout $CI_MERGE_REQUEST_TARGET_BRANCH_NAME
    - jmo scan --repo . --profile balanced --results-dir baseline/

    # Scan current
    - git checkout $CI_COMMIT_SHA
    - jmo scan --repo . --profile balanced --results-dir current/

    # Generate diff
    - jmo diff baseline/ current/ --format md --output diff.md

    # Post MR comment via GitLab API
    - |
      curl --request POST \
        --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
        --data-urlencode "body@diff.md" \
        "$CI_API_V4_URL/projects/$CI_PROJECT_ID/merge_requests/$CI_MERGE_REQUEST_IID/notes"
  only:
    - merge_requests
```

**Complete example:** [docs/examples/gitlab-ci-diff.yml](../docs/examples/gitlab-ci-diff.yml)

### Common Workflows

#### 1. PR Review (Show Only New Issues)

```bash
# Compare branches
jmo diff baseline/ current/ --format md --only new --severity HIGH,CRITICAL

# CI gate: Block if new HIGH/CRITICAL
jmo diff baseline/ current/ --format json --output diff.json
NEW_COUNT=$(jq '(.statistics.new_by_severity.CRITICAL // 0) + (.statistics.new_by_severity.HIGH // 0)' diff.json)
[ "$NEW_COUNT" -eq 0 ] || exit 1
```

#### 2. Sprint Remediation Tracking

```bash
# Track fixes between sprint start and end
jmo diff \
  --scan sprint-start-abc123 \
  --scan sprint-end-def456 \
  --format json \
  --output sprint-kpis.json

# Extract remediation stats
jq '.statistics.resolved_by_severity' sprint-kpis.json
```

#### 3. Release Validation

```bash
# Compare previous release vs current
jmo diff \
  --scan v0.9.0-scan-id \
  --scan v1.0.0-scan-id \
  --format html \
  --output release-validation.html

# Fail if regression (more new than resolved)
NET=$(jq '.statistics.net_change' diff.json)
[ "$NET" -le 0 ] || exit 1
```

#### 4. Compliance Regression Detection

```bash
# Check if PR introduces new OWASP Top 10 findings
jmo diff baseline/ current/ --format json --only new --output diff.json
jq '[.findings.new[] | select(.compliance.owaspTop10_2021 != null)]' diff.json

# Fail if any OWASP findings
COUNT=$(jq '[.findings.new[] | select(.compliance.owaspTop10_2021 != null)] | length' diff.json)
[ "$COUNT" -eq 0 ] || exit 1
```

### Performance

**Targets:**

- <500ms for 1000-finding diffs
- <2s for 10K-finding diffs
- O(n) complexity (fingerprint set operations)

**Optimization Tips:**

- Use `--no-modifications` for faster diffs (30% speedup)
- Filter early: `--severity HIGH,CRITICAL` reduces processing
- SQLite mode is slightly faster (indexed queries)

### Troubleshooting

**"Baseline directory not found"**

- Ensure baseline-results/ exists and contains `summaries/findings.json`
- Run `jmo scan` to generate baseline first

**"Scan ID not found in database"**

- List available scans: `jmo history list`
- Check database path: `--db .jmo/history.db`

**"No findings in diff output"**

- Check filtering: Remove `--severity` or `--only` flags
- Verify scans actually differ: `diff baseline/summaries/findings.json current/summaries/findings.json`

**"Modified findings not detected"**

- Ensure `--no-modifications` not set
- Modification detection requires same fingerprint with different metadata

**"Diff taking too long"**

- Use `--no-modifications` for 30% speedup
- Filter by severity: `--severity CRITICAL,HIGH`
- Check scan sizes: `wc -l baseline/summaries/findings.json`

**For complete workflows and examples, see:** [docs/examples/diff-workflows.md](../docs/examples/diff-workflows.md)

## SLSA Attestation (v1.0.0+)

**What it is:** Supply chain attestation using SLSA (Supply-chain Levels for Software Artifacts) provenance and Sigstore keyless signing. Proves who scanned what, when, and with which tools - making scan results tamper-evident and verifiable.

**Target compliance:** SLSA Level 2 (signed provenance with tamper detection)

**Why it matters:**

- 🔒 **Tamper Evidence**: Detect if scan results were modified after generation
- 📋 **Audit Trail**: Full provenance (commit, tools, profile, CI environment)
- ✅ **Compliance**: Meet SOC 2, ISO 27001, PCI DSS supply chain requirements
- 🔐 **Keyless Signing**: Sigstore OIDC - no key management, uses GitHub/GitLab identity
- 🌐 **Public Transparency**: Rekor transparency log provides independent verification

### Quick Start

**Generate attestation manually:**

```bash
# Scan and attest (creates findings.json.att.json)
jmo scan --repo ./myapp --profile balanced
jmo attest results/summaries/findings.json

# Sign with Sigstore (requires GitHub Actions or GitLab CI)
jmo attest results/summaries/findings.json --sign

# Verify attestation
jmo verify results/summaries/findings.json results/summaries/findings.json.att.json
```

**Auto-attestation in CI (recommended):**

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write  # Required for Sigstore OIDC
    steps:
      - uses: actions/checkout@v4

      - name: Run JMo scan with auto-attestation
        run: |
          jmo scan --repo . --profile balanced --attest --sign

      - name: Upload attestations
        uses: actions/upload-artifact@v4
        with:
          name: attestations
          path: |
            results/summaries/findings.json.att.json
            results/summaries/findings.json.att.sigstore.json
```

### CLI Commands

**jmo attest** — Generate SLSA provenance

```bash
# Generate attestation
jmo attest results/summaries/findings.json

# Output: results/summaries/findings.json.att.json

# With signing (requires CI environment)
jmo attest results/summaries/findings.json --sign

# Output:
#   results/summaries/findings.json.att.json
#   results/summaries/findings.json.att.sigstore.json

# Custom options
jmo attest results/summaries/findings.json \
  --output custom.att.json \
  --sign \
  --rekor-url https://rekor.sigstore.dev
```

**jmo verify** — Verify attestation integrity

```bash
# Basic verification (digest + structure)
jmo verify results/summaries/findings.json results/summaries/findings.json.att.json

# With signature verification (requires .sigstore.json bundle)
jmo verify results/summaries/findings.json results/summaries/findings.json.att.json \
  --signature results/summaries/findings.json.att.sigstore.json

# With tamper detection (checks timestamps, builder consistency, tool versions)
jmo verify results/summaries/findings.json results/summaries/findings.json.att.json \
  --enable-tamper-detection

# With historical comparison (detect tool rollback attacks)
jmo verify results/summaries/findings.json results/summaries/findings.json.att.json \
  --historical-attestations previous-attestations/

# Check Rekor transparency log
jmo verify results/summaries/findings.json results/summaries/findings.json.att.json \
  --signature results/summaries/findings.json.att.sigstore.json \
  --check-rekor
```

### Configuration

**jmo.yml:**

```yaml
# SLSA attestation configuration
attestation:
  # Enable auto-attestation in CI environments
  auto_attest: true

  # Enable auto-signing (requires CI OIDC)
  auto_sign: true

  # Sigstore endpoints (defaults to production)
  fulcio_url: "https://fulcio.sigstore.dev"
  rekor_url: "https://rekor.sigstore.dev"

  # Tamper detection settings
  tamper_detection:
    enabled: true
    max_age_days: 90  # Flag attestations older than 90 days
    max_duration_hours: 24  # Flag scans taking >24 hours

# CLI priority system:
# 1. CLI flags (--attest, --sign) override all
# 2. Environment variables (JMO_ATTEST_ENABLED=true) override config
# 3. Config file settings (auto_attest: true) lowest priority
```

### Provenance Format

**SLSA v1.0 in-toto statement:**

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "findings.json",
      "digest": {
        "sha256": "abc123...",
        "sha384": "def456...",
        "sha512": "ghi789..."
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://jmotools.com/jmo-scan/v1@slsa/v1",
      "externalParameters": {
        "profile": "balanced",
        "tools": ["trivy", "semgrep", "trufflehog"],
        "targets": ["repo1"]
      },
      "internalParameters": {
        "version": "0.9.0",
        "threads": 4,
        "timeout": 600
      }
    },
    "runDetails": {
      "builder": {
        "id": "https://github.com/myorg/myrepo",
        "version": {
          "jmo": "0.9.0",
          "python": "3.11.13"
        }
      },
      "metadata": {
        "invocationId": "550e8400-e29b-41d4-a716-446655440000",
        "startedOn": "2025-11-05T12:34:56Z",
        "finishedOn": "2025-11-05T12:45:23Z"
      }
    }
  }
}
```

### Tamper Detection

**Advanced verification with multiple strategies:**

**Timestamp anomaly detection:**

- Future timestamps (clock manipulation)
- Finish-before-start (impossible)
- Impossible duration (>24h default)
- Stale attestations (>90 days default)

**Builder consistency checks:**

- CI platform changes (GitHub → GitLab)
- Builder version changes
- Repository URL changes

**Tool version rollback detection:**

- Critical tool downgrades (trivy, semgrep, trufflehog)
- Bypass attack detection (reverting to vulnerable versions)

**Suspicious patterns:**

- Empty findings with many tools run
- Path traversal in subject names
- Missing required fields
- Localhost builder IDs

**Severity levels:**

- `CRITICAL`: Definite attack (fail verification immediately)
- `HIGH`: Strong indicator (logged, verification continues)
- `MEDIUM`: Suspicious pattern (logged)
- `LOW`: Minor anomaly (logged)

**Example verification output:**

```bash
$ jmo verify findings.json findings.json.att.json --enable-tamper-detection

✅ Attestation verified successfully
Subject: findings.json
Digest: abc123... (SHA-256)
Builder: https://github.com/myorg/myrepo
Build Time: 2025-11-05T12:45:23Z

🔍 Tamper Detection Results:
  ✅ Timestamp validation: PASSED
  ✅ Builder consistency: PASSED
  ⚠️  Tool version check: trivy downgraded from 0.68.0 to 0.65.0 (MEDIUM)
  ✅ Suspicious patterns: PASSED

No CRITICAL indicators detected.
```

### Keyless Signing (Sigstore)

**How it works:**

1. **OIDC Token**: GitHub Actions/GitLab CI provides identity token
2. **Fulcio CA**: Issues short-lived certificate (10 minutes)
3. **Signing**: Creates signature bundle with certificate
4. **Rekor Log**: Uploads signature to public transparency log
5. **Verification**: Check signature + Rekor entry

**Requirements:**

- GitHub Actions with `id-token: write` permission
- GitLab CI with `GITLAB_CI` environment
- No long-lived keys needed (keyless!)

**GitHub Actions setup:**

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write  # CRITICAL for Sigstore
    steps:
      - name: Scan with attestation
        run: jmo scan --repo . --attest --sign
```

**GitLab CI setup:**

```yaml
security-scan:
  script:
    - jmo scan --repo . --attest --sign
  artifacts:
    paths:
      - results/summaries/findings.json.att.json
      - results/summaries/findings.json.att.sigstore.json
    expire_in: 30 days
```

**Verification workflow:**

```bash
# Verify signature + Rekor entry
jmo verify findings.json findings.json.att.json \
  --signature findings.json.att.sigstore.json \
  --check-rekor

# Output:
# ✅ Signature verified
# ✅ Certificate valid
# ✅ Rekor entry found: https://rekor.sigstore.dev/api/v1/log/entries/...
# ✅ Attestation verified
```

### Docker Integration

**Volume mounts (CRITICAL):**

```bash
# MUST mount attestations directory for persistence
docker run --rm \
  -v $PWD:/scan \
  -v $PWD/results:/results \
  jmo-security:latest scan --repo /scan --attest

# Attestation written to: /results/summaries/findings.json.att.json
```

**Auto-attestation in Docker (no signing):**

```bash
# jmo.yml in project root
docker run --rm \
  -v $PWD:/scan \
  -v $PWD/results:/results \
  jmo-security:latest scan --repo /scan

# Reads auto_attest: true from /scan/jmo.yml
```

**Docker with Sigstore (GitHub Actions):**

```yaml
- name: Scan with Docker + attestation
  env:
    ACTIONS_ID_TOKEN_REQUEST_URL: ${{ env.ACTIONS_ID_TOKEN_REQUEST_URL }}
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: ${{ env.ACTIONS_ID_TOKEN_REQUEST_TOKEN }}
  run: |
    docker run --rm \
      -v $PWD:/scan \
      -v $PWD/results:/results \
      -e ACTIONS_ID_TOKEN_REQUEST_URL \
      -e ACTIONS_ID_TOKEN_REQUEST_TOKEN \
      jmo-security:latest scan --repo /scan --attest --sign
```

### Wizard Integration

**Interactive attestation setup:**

```bash
$ jmo wizard

[Step 6/7] Attestation Configuration
────────────────────────────────────────
SLSA attestation provides tamper-evident scan results with full provenance.

Enable auto-attestation in CI? [Y/n]: y
Enable auto-signing (Sigstore keyless)? [Y/n]: y

✅ Attestation configured in jmo.yml
```

**Post-scan attestation prompt:**

```bash
$ jmo scan --repo ./myapp --profile balanced

Scan complete! 42 findings detected.
Results: /home/user/myapp/results/summaries/

Generate attestation? [Y/n]: y
Sign with Sigstore? (requires CI) [y/N]: n

✅ Attestation generated: results/summaries/findings.json.att.json

Next steps:
  • Verify: jmo verify results/summaries/findings.json results/summaries/findings.json.att.json
  • View: cat results/summaries/findings.json.att.json | jq
```

### Use Cases

**1. Compliance Audits (SOC 2, ISO 27001)**

```bash
# Generate attestation with full provenance
jmo scan --repo . --profile deep --attest --sign

# Provide attestations to auditors
tar czf attestations-q4-2025.tar.gz results/summaries/*.att.json results/summaries/*.sigstore.json

# Auditor verification (independent)
jmo verify findings.json findings.json.att.json --signature findings.json.att.sigstore.json --check-rekor
```

**2. Supply Chain Security (SBOM + Attestation)**

```bash
# Scan with syft + trivy
jmo scan --image myapp:latest --profile balanced --attest --sign

# Attestation proves:
#   • Who scanned (CI identity via Sigstore)
#   • When (timestamp in provenance)
#   • What tools (trivy 0.68.0, syft 1.0.1)
#   • Which image (digest in subject)
```

**3. Regression Prevention (Historical Comparison)**

```bash
# Verify current attestation against history
jmo verify findings.json findings.json.att.json \
  --historical-attestations previous-scans/ \
  --enable-tamper-detection

# Detects:
#   • Tool rollback attacks (trivy 0.68.0 → 0.65.0)
#   • Builder changes (GitHub → GitLab)
#   • Anomalous scan durations
```

**4. Multi-Organization Trust (Open Source Projects)**

```bash
# Maintainer generates attestation
jmo scan --repo . --attest --sign
git add results/summaries/findings.json.att.json results/summaries/findings.json.att.sigstore.json
git commit -m "chore: add scan attestation"

# Downstream consumer verifies
git clone https://github.com/org/project
cd project
jmo verify results/summaries/findings.json results/summaries/findings.json.att.json \
  --signature results/summaries/findings.json.att.sigstore.json \
  --check-rekor

# Rekor provides:
#   • Independent timestamp proof
#   • Non-repudiation (cannot backdate)
#   • Public audit log
```

### Performance

**Attestation generation:**

- Time: <50ms (provenance only)
- Time: <5s (with Sigstore signing)
- Overhead: ~2% of total scan time

**Verification:**

- Digest verification: <10ms
- Full verification: <100ms
- With Rekor check: <500ms (network latency)
- Tamper detection: <200ms (historical comparison)

**Storage:**

- Attestation file: ~2-5 KB (provenance)
- Signature bundle: ~10-20 KB (certificate chain)
- Multi-hash digests: 3× hash algorithms (defense-in-depth)

### Troubleshooting

**"OIDC token acquisition failed"**

- Ensure `id-token: write` permission in GitHub Actions
- Check `GITLAB_CI` environment variable in GitLab CI
- Local signing not supported (keyless requires CI identity)

**"Rekor unavailable"**

- Check Rekor status: `https://status.sigstore.dev`
- Retry with `--rekor-url https://rekor.sigstage.dev` (staging)
- Skip Rekor check: remove `--check-rekor` flag (less secure)

**"Signature verification failed"**

- Ensure signature bundle path correct (`--signature findings.json.att.sigstore.json`)
- Check certificate expiry (10-minute validity)
- Verify with Sigstore directly: `sigstore verify --bundle findings.json.att.sigstore.json findings.json.att.json`

**"CRITICAL tamper detected"**

- Digest mismatch: findings.json modified after attestation
- Finish-before-start: Clock manipulation or corrupted attestation
- Tool rollback: Security bypass attempt (critical tool downgraded)
- Builder change: CI environment inconsistency

**"Attestation file not found"**

- Check output path: `ls results/summaries/*.att.json`
- Auto-attestation requires `auto_attest: true` in jmo.yml
- Docker: verify volume mount `-v $PWD/results:/results`

**For complete workflows and examples, see:** [docs/examples/attestation-workflows.md](../docs/examples/attestation-workflows.md)

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
3. Provides verification link: <https://github.com/Homebrew/install/blob/HEAD/install.sh>
4. Validates downloaded file is not empty
5. Only executes after verification

**Why this matters:** Mitigates supply chain risks by ensuring Homebrew installer hasn't been tampered with during transit or by a compromised mirror.

**Example output during `make tools` on macOS:**

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
| **Deep Audit** | deep | 28 tools | 30-60 min | Weekly, manual | MEDIUM+ |
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

If the failure isn't listed, expand the step logs in GitHub Actions for detailed stderr/stdout. When opening an issue, include the exact failing step and error snippet.

## General Troubleshooting

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

Trends (v1.0.0+ - Statistical trend analysis)

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

Diff (v1.0.0+ - Machine-readable diff)

```bash
jmo diff BASELINE_DIR CURRENT_DIR [--format terminal|json|md|sarif|html] \
  [--output FILE] [--fail-on NEW_CRITICAL|NEW_HIGH] [--severity-filter LEVEL] \
  [--show-context] [--attribution]
```

—

Happy scanning!
