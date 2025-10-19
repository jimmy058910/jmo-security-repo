# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

JMo Security Audit Tool Suite is a terminal-first, cross-platform security audit toolkit that orchestrates multiple scanners with a unified Python CLI, normalized outputs, and an HTML dashboard. The project scans repositories for secrets, vulnerabilities, misconfigurations, and security issues using industry-standard tools.

**Key Philosophy:**

- Two-phase architecture: **scan** (invoke tools, write raw JSON) → **report** (normalize, dedupe, emit unified outputs)
- Unified CommonFinding schema with stable fingerprinting for deduplication
- Profile-based configuration for different scan depths (fast/balanced/deep)
- Resilient to missing tools with fallback mechanisms

## Core Commands

### Development Setup

```bash
# Install Python dev dependencies
make dev-deps

# Install pre-commit hooks (YAML/Actions validation, formatting, linting)
make pre-commit-install

# Install external security tools (semgrep, trivy, checkov, etc.)
make tools

# Verify environment and tool availability
make verify-env

# Format code (shfmt, black, ruff)
make fmt

# Lint code (shellcheck, ruff, bandit, pre-commit)
make lint

# Run tests with coverage (CI requires ≥85%)
make test
```

### Dependency Management

```bash
# Compile requirements-dev.in → requirements-dev.txt (pip-tools)
make deps-compile

# Sync environment to compiled requirements
make deps-sync

# Upgrade pip/setuptools/wheel
make upgrade-pip

# Alternative: use uv for faster compilation/sync
make uv-sync
```

### Version Management (v0.6.1+)

**IMPORTANT: Use the 5-layer version management system to update tool versions.**

```bash
# Check current versions
python3 scripts/dev/update_versions.py --report

# Check for available updates
python3 scripts/dev/update_versions.py --check-latest

# Update a specific tool
python3 scripts/dev/update_versions.py --tool trivy --version 0.68.0

# Sync all Dockerfiles with versions.yaml
python3 scripts/dev/update_versions.py --sync

# Validate consistency (CI uses this)
python3 scripts/dev/update_versions.py --sync --dry-run
```

**Key Files:**

- **[versions.yaml](versions.yaml)** — Single source of truth for all tool versions
- **[scripts/dev/update_versions.py](scripts/dev/update_versions.py)** — Automation script
- **[.github/workflows/version-check.yml](.github/workflows/version-check.yml)** — Weekly CI checks
- **[.github/dependabot.yml](.github/dependabot.yml)** — Python/Docker/Actions updates
- **[docs/VERSION_MANAGEMENT.md](docs/VERSION_MANAGEMENT.md)** — Complete guide

**Critical Rules:**

1. **NEVER manually edit tool versions in Dockerfiles** — Always use `update_versions.py`
2. **ALWAYS sync after updating versions.yaml** — Run `update_versions.py --sync`
3. **CRITICAL: Trivy versions MUST match** — Mismatches cause CVE detection gaps (see ROADMAP #14)
4. **Update critical tools within 7 days** — trivy, trufflehog, semgrep, checkov, syft, zap
5. **Monthly review process** — First Monday: check-latest → review → update → test → commit

**Workflow for Updating Tools:**

```bash
# Step 1: Check for updates
python3 scripts/dev/update_versions.py --check-latest
# Output: [warn] trivy: 0.67.2 → 0.68.0 (UPDATE AVAILABLE)

# Step 2: Review release notes
gh release view v0.68.0 --repo aquasecurity/trivy

# Step 3: Update versions.yaml
python3 scripts/dev/update_versions.py --tool trivy --version 0.68.0

# Step 4: Sync Dockerfiles
python3 scripts/dev/update_versions.py --sync

# Step 5: Verify changes
git diff versions.yaml Dockerfile Dockerfile.slim Dockerfile.alpine

# Step 6: Test locally
make docker-build

# Step 7: Commit
git add versions.yaml Dockerfile*
git commit -m "deps(tools): update trivy to v0.68.0

- trivy: 0.67.2 → 0.68.0 (CVE database updates)

Related: ROADMAP #14, Issue #46"
```

**See [docs/VERSION_MANAGEMENT.md](docs/VERSION_MANAGEMENT.md) for complete documentation.**

### Running Scans

```bash
# Interactive wizard (recommended for first-time users)
jmotools wizard

# Non-interactive wizard with defaults
jmotools wizard --yes

# Fast scan with wrapper command
jmotools fast --repos-dir ~/repos

# Balanced scan (default profile)
jmotools balanced --repos-dir ~/repos

# Full deep scan
jmotools full --repos-dir ~/repos

# Manual scan using Python CLI - Repository scanning
python3 scripts/cli/jmo.py scan --repos-dir ~/repos --profile-name balanced --human-logs

# Multi-target scanning (v0.6.0+)
# Scan container images
python3 scripts/cli/jmo.py scan --image nginx:latest --tools trivy syft

# Scan IaC files
python3 scripts/cli/jmo.py scan --terraform-state infrastructure.tfstate --tools checkov trivy

# Scan live web URLs (DAST)
python3 scripts/cli/jmo.py scan --url https://example.com --tools zap

# Scan GitLab repositories
python3 scripts/cli/jmo.py scan --gitlab-repo mygroup/myrepo --gitlab-token TOKEN --tools trufflehog

# Scan Kubernetes clusters
python3 scripts/cli/jmo.py scan --k8s-context prod --k8s-all-namespaces --tools trivy

# Scan multiple target types in one command
python3 scripts/cli/jmo.py scan \
  --repo ./myapp \
  --image myapp:latest \
  --terraform-state infrastructure.tfstate \
  --url https://myapp.com \
  --gitlab-repo myorg/backend \
  --k8s-context prod \
  --results-dir ./comprehensive-audit

# Aggregate and report (all target types)
python3 scripts/cli/jmo.py report ./results --profile --human-logs

# CI mode: scan + report + threshold gating (multi-target support)
python3 scripts/cli/jmo.py ci --image nginx:latest --url https://api.example.com --fail-on HIGH --profile
```

### Running a Single Test

```bash
# Run specific test file
pytest tests/unit/test_common_and_sarif.py -v

# Run specific test function
pytest tests/unit/test_common_and_sarif.py::test_write_sarif -v

# Run with coverage
pytest tests/unit/ --cov=scripts --cov-report=term-missing

# Run adapter tests (useful when adding new tool adapters)
pytest tests/adapters/test_gitleaks_adapter.py -v

# Run integration tests (end-to-end CLI workflows)
pytest tests/integration/test_cli_scan_ci.py -v

# Run tests by category
pytest tests/unit/ -v         # All unit tests
pytest tests/adapters/ -v     # All adapter tests
pytest tests/reporters/ -v    # All reporter tests
pytest tests/integration/ -v  # All integration tests
```

## Architecture

### Directory Structure

```text
scripts/
├── cli/
│   ├── jmo.py          # Main CLI entry point (scan/report/ci commands)
│   ├── jmotools.py     # Wrapper commands (fast/balanced/full/setup)
│   └── wizard.py       # Interactive wizard for guided scanning
├── core/
│   ├── normalize_and_report.py  # Aggregation engine: loads tool outputs, dedupes, enriches
│   ├── config.py       # Config loader for jmo.yml
│   ├── suppress.py     # Suppression logic (jmo.suppress.yml)
│   ├── common_finding.py  # CommonFinding schema and fingerprinting
│   ├── adapters/       # Tool output parsers (gitleaks, semgrep, trivy, etc.)
│   │   ├── gitleaks_adapter.py
│   │   ├── semgrep_adapter.py
│   │   ├── trivy_adapter.py
│   │   └── ...
│   └── reporters/      # Output formatters
│       ├── basic_reporter.py    # JSON + Markdown
│       ├── yaml_reporter.py     # YAML (optional, requires PyYAML)
│       ├── html_reporter.py     # Interactive dashboard
│       ├── sarif_reporter.py    # SARIF 2.1.0
│       └── suppression_reporter.py  # Suppression summary
└── dev/               # Helper scripts for tool installation and CI

tests/
├── unit/              # Core logic tests
├── adapters/          # Adapter tests with fabricated JSON fixtures
├── reporters/         # Reporter tests
├── integration/       # End-to-end CLI tests
└── cli/               # CLI argument and smoke tests
```

### Key Concepts

**Two-Phase Workflow:**

1. **Scan Phase** (`jmo scan`):
   - **v0.5.x and earlier:** Discovers repos from `--repo`, `--repos-dir`, or `--targets`
   - **v0.6.0+:** Multi-target scanning across 6 target types:
     - **Repositories:** `--repo`, `--repos-dir`, `--targets` (local Git repos)
     - **Container Images:** `--image`, `--images-file` (Docker/OCI images)
     - **IaC Files:** `--terraform-state`, `--cloudformation`, `--k8s-manifest`
     - **Web URLs:** `--url`, `--urls-file`, `--api-spec` (DAST scanning)
     - **GitLab Repos:** `--gitlab-repo`, `--gitlab-group` (GitLab integration)
     - **Kubernetes Clusters:** `--k8s-context`, `--k8s-namespace`, `--k8s-all-namespaces`
   - Invokes tools in parallel (configurable threads)
   - Writes raw JSON to results directories by target type:
     - `results/individual-repos/<repo>/{tool}.json`
     - `results/individual-images/<image>/{tool}.json`
     - `results/individual-iac/<file>/{tool}.json`
     - `results/individual-web/<domain>/{tool}.json`
     - `results/individual-gitlab/<group>_<repo>/{tool}.json`
     - `results/individual-k8s/<context>_<namespace>/{tool}.json`
   - Supports timeouts, retries, and per-tool overrides
   - Gracefully handles missing tools with `--allow-missing-tools` (writes empty stubs)

2. **Report Phase** (`jmo report`):
   - Scans all 6 target type directories for tool outputs
   - Loads all tool outputs via adapters
   - Normalizes to CommonFinding schema (v1.2.0 with compliance fields)
   - Deduplicates by fingerprint ID across all target types
   - Enriches findings with compliance frameworks (OWASP, CWE, CIS, NIST CSF, PCI DSS, ATT&CK)
   - Enriches Trivy findings with Syft SBOM context
   - Writes unified outputs: `findings.json`, `SUMMARY.md`, `dashboard.html`, `findings.sarif`, `COMPLIANCE_SUMMARY.md`, etc.
   - Supports severity-based failure thresholds (`--fail-on HIGH`)

**CommonFinding Schema:**

All tool outputs are converted to a unified shape defined in `docs/schemas/common_finding.v1.json`:

- **Required fields:** `schemaVersion`, `id` (fingerprint), `ruleId`, `severity`, `tool` (name/version), `location` (path/lines), `message`
- **Optional fields:** `title`, `description`, `remediation`, `references`, `tags`, `cvss`, `context`, `raw` (original tool payload)
- **Compliance field (v1.2.0+):** `compliance` object with 6 framework mappings:
  - `owaspTop10_2021`: Array of OWASP Top 10 categories (e.g., ["A02:2021", "A06:2021"])
  - `cweTop25_2024`: Array of CWE Top 25 entries with rank, category
  - `cisControlsV8_1`: Array of CIS Controls with Implementation Group (IG1/IG2/IG3)
  - `nistCsf2_0`: Array of NIST CSF mappings (function, category, subcategory)
  - `pciDss4_0`: Array of PCI DSS 4.0 requirements with priority
  - `mitreAttack`: Array of ATT&CK techniques (tactic, technique, subtechnique)
- **Risk field (v1.1.0+):** `risk` object with CWE, confidence, likelihood, impact
- **Fingerprinting:** Deterministic ID computed from `tool | ruleId | path | startLine | message[:120]` to enable cross-run deduplication
- **Schema Versions:**
  - **1.0.0:** Basic finding format
  - **1.1.0:** Added `risk`, `context`, enhanced remediation
  - **1.2.0:** Added `compliance` field (v0.5.1+), auto-enriched during reporting

**Profiles (v0.5.0):**

Configuration via `jmo.yml` supports named profiles for different scan depths:

- **fast:** 3 best-in-breed tools (trufflehog, semgrep, trivy), 300s timeout, 8 threads, 5-8 minutes
  - Use case: Pre-commit checks, quick validation, CI/CD gate
  - Coverage: Verified secrets, SAST, SCA, containers, IaC, backup secrets scanning

- **balanced:** 7 production-ready tools (trufflehog, semgrep, syft, trivy, checkov, hadolint, zap), 600s timeout, 4 threads, 15-20 minutes
  - Use case: CI/CD pipelines, regular audits, production scans
  - Coverage: Verified secrets, SAST, SCA, containers, IaC, Dockerfiles, DAST

- **deep:** 11 comprehensive tools (trufflehog, noseyparker, semgrep, bandit, syft, trivy, checkov, hadolint, zap, falco, afl++), 900s timeout, 2 threads, 30-60 minutes, retries enabled
  - Use case: Security audits, compliance scans, pre-release validation
  - Coverage: Dual secrets scanners, dual Python SAST, SBOM, SCA, IaC, DAST, runtime security, fuzzing

Profiles can override tools, timeouts, threads, and per-tool flags. Use `--profile-name <name>` to apply.

**Interactive Wizard:**

The wizard (`scripts/cli/wizard.py`) provides guided onboarding for first-time users:

- **Interactive mode:** Step-by-step prompts for profile selection, target configuration, execution mode (Docker/native)
- **Non-interactive mode:** `--yes` flag uses smart defaults for automation
- **Artifact generation:** Can emit Makefile targets (`--emit-make-target`), shell scripts (`--emit-script`), or GitHub Actions workflows (`--emit-gha`) for reusable configurations
- **Docker integration:** Automatically detects Docker availability and offers zero-installation scanning
- Auto-opens results dashboard after scan completion

### Tool Adapters

Each adapter in `scripts/core/adapters/` follows this pattern:

1. Check if output file exists
2. Parse tool-specific JSON format
3. Map to CommonFinding schema
4. Generate stable fingerprint ID
5. Return list of findings

**Supported Tools (v0.6.2):**

- **Secrets:** trufflehog (verified, 95% false positive reduction), noseyparker (optional, deep profile, local + Docker fallback)
- **SAST:** semgrep (multi-language), bandit (Python-specific, deep profile)
- **SBOM+Vuln:** syft (SBOM generation), trivy (vuln/misconfig/secrets scanning)
- **IaC:** checkov (policy-as-code)
- **Dockerfile:** hadolint (best practices)
- **DAST:** OWASP ZAP (web security, runtime vulnerabilities), Nuclei (fast vulnerability scanner with 4000+ templates, API security)
- **Runtime Security:** Falco (container/K8s monitoring, eBPF-based, deep profile)
- **Fuzzing:** AFL++ (coverage-guided fuzzing, deep profile)

**Removed Tools (v0.5.0):**

- ❌ gitleaks → Replaced by trufflehog (better verification, fewer false positives)
- ❌ tfsec → Deprecated since 2021, functionality merged into trivy
- ❌ osv-scanner → Trivy provides superior container/dependency scanning

**Nosey Parker Fallback:**

When local binary is missing/fails, automatically falls back to Docker-based runner via `scripts/core/run_noseyparker_docker.sh`. Requires Docker installed and `ghcr.io/praetorian-inc/noseyparker:latest` image.

### Multi-Target Scanning Architecture (v0.6.0+)

**Overview:**

v0.6.0 expands scanning beyond local Git repositories to 5 additional target types, enabling comprehensive security coverage across an organization's entire infrastructure.

**Supported Target Types:**

1. **Repositories** (existing): Local Git repos via `--repo`, `--repos-dir`, `--targets`
2. **Container Images** (NEW): Docker/OCI images via `--image`, `--images-file`
3. **IaC Files** (NEW): Terraform/CloudFormation/K8s manifests via `--terraform-state`, `--cloudformation`, `--k8s-manifest`
4. **Web URLs** (NEW): Live web apps/APIs via `--url`, `--urls-file`, `--api-spec`
5. **GitLab Repos** (NEW): GitLab-hosted repos via `--gitlab-repo`, `--gitlab-group`
6. **Kubernetes Clusters** (NEW): Live K8s clusters via `--k8s-context`, `--k8s-namespace`, `--k8s-all-namespaces`

**Implementation Pattern:**

All scan targets follow a consistent pattern in [jmo.py](scripts/cli/jmo.py):

```python
# 1. Target Collection Function
def _iter_images(args) -> list[str]:
    """Collect container images from CLI arguments."""
    images = []
    if getattr(args, "image", None):
        images.append(args.image)
    if getattr(args, "images_file", None):
        # Load from file, skip comments/empty lines
        ...
    return images

# 2. Scan Job Function (ThreadPoolExecutor)
def job_image(image: str) -> tuple[str, dict[str, bool]]:
    """Scan a container image with trivy and syft."""
    # Sanitize name for directory
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", image)
    out_dir = results_dir / "individual-images" / safe_name
    out_dir.mkdir(parents=True, exist_ok=True)

    # Tool invocation
    if "trivy" in tools:
        cmd = ["trivy", "image", "-q", "-f", "json", image, "-o", str(out)]
        rc, _, _, used = _run_cmd(cmd, timeout, retries, ok_rcs=(0, 1))

    # Return status
    return image, statuses

# 3. Parallel Execution
with ThreadPoolExecutor(max_workers=max_workers) as ex:
    for image in images:
        futures.append(ex.submit(job_image, image))
    for fut in as_completed(futures):
        name, statuses = fut.result()
        _log(args, "INFO", f"scanned image {name}: {statuses}")
```

**Key Architectural Decisions:**

- **Parallel execution:** All target types use ThreadPoolExecutor for concurrent scanning
- **Consistent logging:** Each scan target type has distinct log prefix (`repo`, `image`, `IaC`, `URL`, `GitLab`, `K8s`)
- **Directory isolation:** Each target type writes to separate `individual-{type}/` directories
- **Error resilience:** `--allow-missing-tools` writes empty stubs, allowing partial results
- **Unified reporting:** `normalize_and_report.py` scans all 6 directories and deduplicates across targets

**Tool Assignments by Target Type:**

| Target Type | Primary Tools | Secondary Tools |
|-------------|---------------|-----------------|
| Repositories | trufflehog, semgrep | trivy, noseyparker, bandit |
| Container Images | trivy, syft | - |
| IaC Files | checkov, trivy | - |
| Web URLs | zap | - |
| GitLab Repos | trufflehog | - |
| Kubernetes | trivy | - |

**CLI Argument Design:**

- **Single target:** `--image nginx:latest`
- **Batch file:** `--images-file images.txt` (one per line, # comments supported)
- **Type-specific:** `--terraform-state` vs `--cloudformation` for IaC type detection
- **Context-aware:** `--gitlab-url`, `--gitlab-token` for authentication
- **Namespace control:** `--k8s-namespace` vs `--k8s-all-namespaces`

**Results Aggregation:**

[normalize_and_report.py:75-132](scripts/core/normalize_and_report.py#L75-L132) scans all target directories:

```python
target_dirs = [
    results_dir / "individual-repos",
    results_dir / "individual-images",
    results_dir / "individual-iac",
    results_dir / "individual-web",
    results_dir / "individual-gitlab",
    results_dir / "individual-k8s",
]

for target_dir in target_dirs:
    if not target_dir.exists():
        continue
    for target in sorted(p for p in target_dir.iterdir() if p.is_dir()):
        # Load all tool outputs (trivy, syft, checkov, zap, trufflehog, etc.)
        # Findings deduplicated by fingerprint ID across all targets
```

**Benefits:**

- **Unified security posture:** Single tool for all asset types
- **Reduced tooling sprawl:** No separate container scanners, IaC validators, DAST tools
- **Consistent findings:** All findings normalized to CommonFinding schema
- **Compliance automation:** All findings enriched with 6 compliance frameworks
- **CI/CD efficiency:** Multi-target scanning in single pipeline step

### Output Formats

Report phase writes to `<results_dir>/summaries/`:

- `findings.json` — Unified normalized findings (machine-readable)
- `SUMMARY.md` — Human-readable summary with severity counts and top rules
- `findings.yaml` — Optional YAML format (requires `pip install -e ".[reporting]"`)
- `dashboard.html` — Self-contained interactive HTML dashboard
- `findings.sarif` — SARIF 2.1.0 for code scanning platforms (GitHub, GitLab, etc.)
- `SUPPRESSIONS.md` — Summary of suppressed findings (when `jmo.suppress.yml` is present)
- `timings.json` — Profiling data (when `--profile` flag used)

### Configuration

**jmo.yml** controls tool selection, output formats, thresholds, and profiles (v0.5.0):

```yaml
default_profile: balanced
tools: [trufflehog, semgrep, syft, trivy, checkov, hadolint, zap]
outputs: [json, md, yaml, html, sarif]
fail_on: ""  # Optional: CRITICAL/HIGH/MEDIUM/LOW/INFO
retries: 0   # Global retry count for flaky tools
threads: 4   # Default parallelism

profiles:
  fast:
    tools: [trufflehog, semgrep, trivy]
    threads: 8
    timeout: 300
    per_tool:
      semgrep:
        flags: ["--exclude", "node_modules", "--exclude", ".git"]
      trivy:
        flags: ["--no-progress", "--scanners", "vuln,secret,misconfig"]

  balanced:
    tools: [trufflehog, semgrep, syft, trivy, checkov, hadolint, zap]
    threads: 4
    timeout: 600
    per_tool:
      zap:
        flags: ["-config", "api.disablekey=true", "-config", "spider.maxDuration=5"]

  deep:
    tools: [trufflehog, noseyparker, semgrep, bandit, syft, trivy, checkov, hadolint, zap, falco, afl++]
    threads: 2
    timeout: 900
    retries: 1
    per_tool:
      noseyparker:
        timeout: 1200
      afl++:
        timeout: 1800
        flags: ["-m", "none"]

per_tool:
  trivy:
    flags: ["--no-progress"]
    timeout: 1200
```

**jmo.suppress.yml** (optional) filters findings:

```yaml
suppressions:

  - id: "fingerprint-id-here"
    reason: "False positive, accepted risk"

  - ruleId: "G101"
    path: "tests/*"
    reason: "Test files excluded"
```

## Testing Strategy

- **Unit tests** (`tests/unit/`): Core logic, config parsing, helpers
- **Adapter tests** (`tests/adapters/`): Parse fabricated tool JSON fixtures, validate CommonFinding mapping
- **Reporter tests** (`tests/reporters/`): Verify output formats (JSON/MD/YAML/HTML/SARIF)
- **Integration tests** (`tests/integration/`): End-to-end CLI flows, profile/thread behavior, CI gating

**Test Patterns:**

- Use `tmp_path` fixture for isolated file operations
- Fabricate minimal tool JSONs to test adapters
- Mock subprocess calls when testing tool invocation logic
- Assert on specific exit codes for `--fail-on` thresholds

**Coverage:**

CI enforces ≥85% coverage (see [.github/workflows/ci.yml](.github/workflows/ci.yml)). Upload to Codecov uses OIDC (tokenless) for public repos.

## CI/CD

**GitHub Actions Workflows:**

The project uses 2 consolidated workflows for all CI/CD operations:

1. **[.github/workflows/ci.yml](.github/workflows/ci.yml)** — Primary CI workflow
   - `quick-checks` job: actionlint, yamllint, deps-compile freshness, guardrails (2-3 min)
   - `test-matrix` job: Ubuntu/macOS × Python 3.10/3.11/3.12 (parallel, independent)
   - `lint-full` job: Full pre-commit suite (nightly scheduled runs only)
   - Triggers: push, pull_request, workflow_dispatch, schedule (nightly at 6 AM UTC)

2. **[.github/workflows/release.yml](.github/workflows/release.yml)** — Release automation
   - `pypi-publish` job: Build and publish to PyPI (Trusted Publishers OIDC)
   - `docker-build` job: Multi-arch Docker images (full/slim/alpine variants)
   - `docker-scan` job: Trivy vulnerability scanning
   - `docker-hub-readme` job: Sync README to Docker Hub (future)
   - Triggers: version tags (`v*`), workflow_dispatch

**Pre-commit Hooks:**

Configured via `.pre-commit-config.yaml`:

- **Formatting:** Black, Ruff, shfmt (shell scripts)
- **Linting:** Ruff, shellcheck, yamllint, markdownlint
- **Validation:** actionlint (GitHub Actions), check-yaml, detect-private-key
- **Security:** Bandit (local only; skipped in CI pre-commit stage but covered by `make lint`)

Run `make pre-commit-run` before committing. CI enforces these checks.

**Technical Debt Management:**

**IMPORTANT PRINCIPLE: Never leave technical debt when found. Fix it immediately.**

When working on any task and you encounter linting issues, failing tests, or code quality problems:

1. **Fix all issues comprehensively**, not just the ones related to your current task
2. **Example:** If you add content to CHANGELOG.md and markdownlint shows 8 warnings (3 from your changes + 5 from previous releases), fix all 8 warnings, not just the 3 new ones
3. **Rationale:**
   - Technical debt compounds quickly if left unaddressed
   - "Boy Scout Rule": Leave the codebase better than you found it
   - Future contributors shouldn't have to fix your accumulated debt
   - Linting issues indicate real problems (accessibility, compatibility, maintainability)
4. **Common scenarios:**
   - Markdown linting: Fix ALL MD036 (emphasis as heading), MD032 (blanks around lists), MD040 (code fence language) issues
   - Python linting: Fix all ruff/black/bandit violations in touched files
   - YAML linting: Fix all yamllint violations when editing workflow files
   - Shell linting: Fix all shellcheck issues when editing bash scripts

**Documentation debt specifically:**

- Markdown linting failures are NOT cosmetic; they affect:
  - Screen reader accessibility (heading hierarchy)
  - Rendering consistency across platforms
  - Copy-paste reliability of code blocks
  - Link resolution in different viewers
- Always run `pre-commit run markdownlint --all-files` after documentation changes
- Fix issues incrementally: use `pre-commit run markdownlint --files <file>` to verify fixes

**CI/CD Common Fixes (Lessons Learned):**

When working with release.yml or ci.yml workflows, apply these proven fixes:

1. **Docker Tag Extraction:**
   - ❌ DON'T: Construct tags manually from `github.ref_name` (includes 'v' prefix)
   - ✅ DO: Extract tag directly from `metadata-action` output (strips 'v' automatically)
   ```yaml
   TEST_TAG=$(echo "${{ steps.meta.outputs.tags }}" | head -n1 | cut -d':' -f2)
   ```

2. **Actionlint Parameters:**
   - ❌ DON'T: Use deprecated `fail_on_error: true`
   - ✅ DO: Use current API `fail_level: error`
   ```yaml
   - uses: reviewdog/action-actionlint@v1
     with:
       fail_level: error
   ```

3. **Docker Image Testing:**
   - ❌ DON'T: Use `jmo --version` (CLI doesn't support top-level version flag)
   - ✅ DO: Use `jmo --help` and `jmo scan --help` (tests CLI works correctly)
   ```yaml
   docker run --rm jmo-security:tag --help
   docker run --rm jmo-security:tag scan --help
   ```

4. **SARIF Upload Permissions:**
   - ❌ DON'T: Omit `security-events: write` permission (causes "Resource not accessible by integration")
   - ✅ DO: Add `security-events: write` to workflow permissions
   ```yaml
   permissions:
     security-events: write  # Required for uploading SARIF to GitHub Security
   ```

5. **Docker Hub README Sync:**
   - Use `peter-evans/dockerhub-description@v4` (not v3)
   - Gate with repository variable: `if: vars.DOCKERHUB_ENABLED == 'true'`
   - Requires secrets: `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN` (PAT with read/write/delete scope)
   - Only run on version tags: `if: startsWith(github.ref, 'refs/tags/v')`

## Common Development Tasks

### Adding a New Tool Adapter

1. Create `scripts/core/adapters/<tool>_adapter.py` following existing patterns:
   - `load_<tool>(path: Path) -> List[Dict[str, Any]]`
   - Map tool output to CommonFinding schema
   - Generate stable fingerprint via `common_finding.py` utilities
2. Update `scripts/core/normalize_and_report.py`:
   - Import the loader
   - Add to the loop in `gather_results()`
3. Update `scripts/cli/jmo.py`:
   - Add tool invocation logic to `cmd_scan()`
   - Update `_write_stub()` for empty JSON structure
4. Add fabricated test JSON to `tests/adapters/test_<tool>_adapter.py`
5. Update docs: `README.md`, `QUICKSTART.md`, `jmo.yml` tool lists

### Modifying Output Formats

- Reporters live in `scripts/core/reporters/`
- JSON/Markdown: `basic_reporter.py`
- YAML: `yaml_reporter.py` (requires PyYAML)
- HTML: `html_reporter.py` (self-contained template)
- SARIF: `sarif_reporter.py` (maps to SARIF 2.1.0 schema)
- Update `scripts/cli/jmo.py:cmd_report()` to call new reporter
- Add tests in `tests/reporters/`

### Changing CLI Behavior

- Main CLI: `scripts/cli/jmo.py`
- Subcommands: `scan`, `report`, `ci`
- When modifying flags/behavior:
  1. Update `parse_args()` function
  2. Update `README.md`, `QUICKSTART.md`, `SAMPLE_OUTPUTS.md`
  3. Add/update tests in `tests/cli/` and `tests/integration/`

### Updating Dependencies

- **Runtime deps:** Minimal; declared in `pyproject.toml` under `[project.dependencies]` (currently empty)
- **Optional deps:** `[project.optional-dependencies]` for reporters (PyYAML, jsonschema)
- **Dev deps:** `requirements-dev.in` → compile with `make deps-compile` → commit `requirements-dev.txt`
- **External tools:** Install via `make tools` (see `scripts/dev/install_tools.sh`)
- **Pre-commit hooks:** Update with `pre-commit autoupdate`

CI validates that `requirements-dev.txt` matches `requirements-dev.in` on PRs.

## Claude Skills (Dev-Only, Not Committed)

**IMPORTANT: The `.claude/skills/` directory is gitignored and NOT part of the committed codebase.** Skills are local development aids for contributors using Claude Code. They are referenced in this file to help Claude understand when to use them during local development.

This project uses **specialized skills** to guide complex, repetitive workflows. Skills are comprehensive knowledge bases that ensure consistency, reduce errors, and accelerate development.

### Why Skills Matter

Skills centralize expertise for complex tasks, providing:

- Step-by-step workflows with verification checklists
- Real-world examples and proven patterns
- Error handling and troubleshooting guides
- Output artifact specifications
- Success criteria verification

**Time Savings:** Skills reduce task completion time by 50-75% (2-4 hours per task) and ensure consistency across the codebase.

### Available Skills by Category

**Code Generation:**

- [jmo-adapter-generator](.claude/skills/jmo-adapter-generator/SKILL.md) — Add new tool integrations (2-3 hour savings)
- [jmo-target-type-expander](.claude/skills/jmo-target-type-expander/SKILL.md) — Add new scan target types (3-4 hour savings)

**Quality Assurance:**

- [jmo-test-fabricator](.claude/skills/jmo-test-fabricator/SKILL.md) — Write adapter test suites with ≥85% coverage (1-2 hour savings)
- [jmo-compliance-mapper](.claude/skills/jmo-compliance-mapper/SKILL.md) — Map findings to 6 compliance frameworks (30-60 min savings)

**Operations:**

- [jmo-profile-optimizer](.claude/skills/jmo-profile-optimizer/SKILL.md) — Optimize scan performance and reliability (1-2 hour savings)
- [jmo-ci-debugger](.claude/skills/jmo-ci-debugger/SKILL.md) — Debug GitHub Actions and CI/CD failures (30-60 min savings)

**Documentation:**

- [jmo-documentation-updater](.claude/skills/jmo-documentation-updater/SKILL.md) — Maintain docs consistency and structure (30-45 min savings)

**Workflow Automation:**

- [dev-helper](.claude/skills/dev-helper/SKILL.md) — Version bumps, release prep, issue triage (15-30 min savings)
- [community-manager](.claude/skills/community-manager/SKILL.md) — Track feedback, draft responses (30-60 min savings)
- [content-generator](.claude/skills/content-generator/SKILL.md) — Create marketing content (1-2 hour savings)
- [job-search-helper](.claude/skills/job-search-helper/SKILL.md) — Resume bullets, interview prep (30-60 min savings)

**Complete catalog:** [.claude/skills/INDEX.md](.claude/skills/INDEX.md) (11 skills, ~14,300 lines of guidance)

### When to Use Skills

**Use skills proactively when:**

| Task | Skill to Use | Trigger |
|------|--------------|---------|
| Adding new tool adapter | jmo-adapter-generator | "Add support for [tool]" |
| Writing adapter tests | jmo-test-fabricator | "Write tests for [tool] adapter" |
| Debugging CI failures | jmo-ci-debugger | "CI is failing", "GitHub Actions not working" |
| Updating documentation | jmo-documentation-updater | "Update docs for [feature]" |
| Optimizing scan performance | jmo-profile-optimizer | "Scans are too slow", "Too many timeouts" |
| Adding new target type | jmo-target-type-expander | "Scan [AWS/npm/GraphQL/etc.]" |
| Mapping to compliance frameworks | jmo-compliance-mapper | "What frameworks does [CWE] map to?" |
| Preparing for release | dev-helper | "Bump version to X.Y.Z" |

**Skills are guides, not rigid requirements.** If project constraints require a different approach, document the deviation in your PR description or code comments. Consider updating the skill if the deviation becomes a common pattern.

### Common Skill Workflows

Skills compose together for end-to-end features. See [.claude/skills/SKILL_WORKFLOWS.md](.claude/skills/SKILL_WORKFLOWS.md) for detailed multi-skill workflows.

#### Example: Add New Tool (Full Stack)

1. **jmo-adapter-generator** — Create `snyk_adapter.py` and `test_snyk_adapter.py`
2. **jmo-test-fabricator** — Expand test suite to ≥85% coverage
3. **jmo-compliance-mapper** — Add Snyk-specific rule mappings (if needed)
4. **jmo-documentation-updater** — Update README.md, QUICKSTART.md, USER_GUIDE.md

Time: 4-6 hours (vs. 8-12 hours without skills)

#### Example: Performance Investigation

1. **jmo-profile-optimizer** — Analyze `timings.json`, identify bottlenecks
2. **jmo-ci-debugger** — Fix CI timeout configuration
3. **jmo-documentation-updater** — Document performance tuning in USER_GUIDE.md

Time: 2-3 hours (vs. 4-6 hours without skills)

### Skill Maintenance

Skills use **Semantic Versioning** and are updated on a regular schedule:

- **Weekly:** jmo-ci-debugger (GitHub Actions API changes)
- **Monthly:** jmo-documentation-updater (documentation structure adjustments)
- **Quarterly:** jmo-compliance-mapper (MITRE ATT&CK updates)
- **Annually:** jmo-compliance-mapper (CWE Top 25, OWASP Top 10, NIST CSF, CIS Controls)
- **As Needed:** All others (when core architecture changes)

See [.claude/skills/INDEX.md#skill-maintenance](.claude/skills/INDEX.md#skill-maintenance) for complete versioning and update process.

## Important Conventions

### Tool Invocation

- Tools invoked via `subprocess.run()` without shell (`shell=False`)
- Respect tool-specific exit codes:
  - semgrep: 0 (clean), 1 (findings), 2 (errors) — treat 0/1/2 as success when output exists
  - trivy/checkov/bandit: 0/1 treated as success
  - gitleaks/trufflehog: 0/1 treated as success
- Timeout enforcement per tool (configurable via `jmo.yml` per_tool overrides)
- Retry logic: global `retries` or per-profile; skips retries for "findings" exit codes

### Logging

- Machine JSON logs by default (structured for parsing)
- Human-friendly colored logs with `--human-logs` flag
- Log levels: DEBUG/INFO/WARN/ERROR (controlled by `--log-level` or config)
- Always log to stderr, never stdout (stdout reserved for tool outputs)

### Security Practices

- Never commit secrets (pre-commit hook checks via `detect-private-key`)
- Bandit scans `scripts/` with strict config (`bandit.yaml`)
- Test files scanned with B101,B404 skipped
- No shell=True in subprocess calls (use list args)
- Validate all file paths from user input

### Results Directory Layout (v0.6.0+)

```text
results/
├── individual-repos/          # Repository scans (existing)
│   └── <repo-name>/
│       ├── trufflehog.json
│       ├── semgrep.json
│       ├── trivy.json
│       └── ...
├── individual-images/         # v0.6.0: Container image scans
│   └── <sanitized-image>/
│       ├── trivy.json
│       └── syft.json
├── individual-iac/            # v0.6.0: IaC file scans
│   └── <file-stem>/
│       ├── checkov.json
│       └── trivy.json
├── individual-web/            # v0.6.0: Web app/API scans
│   └── <domain>/
│       └── zap.json
├── individual-gitlab/         # v0.6.0: GitLab repository scans
│   └── <group>_<repo>/
│       └── trufflehog.json
├── individual-k8s/            # v0.6.0: Kubernetes cluster scans
│   └── <context>_<namespace>/
│       └── trivy.json
└── summaries/                 # Aggregated reports (all targets)
    ├── findings.json          # Unified findings from all target types
    ├── SUMMARY.md             # Summary with severity counts
    ├── findings.yaml          # Optional YAML format
    ├── dashboard.html         # Interactive dashboard
    ├── findings.sarif         # SARIF 2.1.0 format
    ├── SUPPRESSIONS.md        # Suppression summary
    ├── COMPLIANCE_SUMMARY.md  # v0.5.1: Multi-framework compliance
    ├── PCI_DSS_COMPLIANCE.md  # v0.5.1: PCI DSS report
    ├── attack-navigator.json  # v0.5.1: MITRE ATT&CK Navigator
    └── timings.json           # Performance profiling (when --profile used)
```

**Important:** Never change default paths without updating all tests and documentation.

**v0.6.0 Note:** `normalize_and_report.py` automatically scans all 6 target directories. Findings are deduplicated across all target types by fingerprint ID.

## Release Process

1. Bump version in `pyproject.toml` under `[project] version`
2. Update `CHANGELOG.md` with changes
3. Commit with message: `release: vX.Y.Z`
4. Create and push tag: `git tag vX.Y.Z && git push --tags`
5. CI publishes to PyPI automatically using Trusted Publishers (OIDC)

**Prerequisites:**

- Configure repo as Trusted Publisher in PyPI settings (one-time setup)
- No `PYPI_API_TOKEN` required with OIDC workflow

## Troubleshooting

### Tests Failing

- Run `make test` locally with `--maxfail=1` to stop at first failure
- Check coverage with `pytest --cov --cov-report=term-missing`
- Ensure `requirements-dev.txt` is up to date: `make deps-compile`

### Tool Not Found

- Run `make verify-env` to see detected tools and install hints
- Install missing tools: `make tools` (Linux/WSL/macOS detection)
- Use `--allow-missing-tools` to write empty stubs instead of failing

### Pre-commit Hook Failures

- Run `make pre-commit-run` to see all violations
- Format code: `make fmt`
- Lint code: `make lint`
- Update hooks: `pre-commit autoupdate`

### CI Failures

- Matrix tests run on Ubuntu/macOS × Python 3.10/3.11/3.12
- Check coverage ≥85% threshold
- Verify `requirements-dev.txt` matches `requirements-dev.in`
- Pre-commit checks must pass (actionlint, yamllint, etc.)

## Additional Resources

- **Claude Skills Index: [.claude/skills/INDEX.md](.claude/skills/INDEX.md)** — Complete skill catalog with workflows
- User Guide: [docs/USER_GUIDE.md](docs/USER_GUIDE.md)
- Quick Start: [QUICKSTART.md](QUICKSTART.md)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)
- Testing: [TEST.md](TEST.md)
- Release Process: [docs/RELEASE.md](docs/RELEASE.md)
- **Version Management: [docs/VERSION_MANAGEMENT.md](docs/VERSION_MANAGEMENT.md)** (v0.6.1+)
- CommonFinding Schema: [docs/schemas/common_finding.v1.json](docs/schemas/common_finding.v1.json)
- Copilot Instructions: [.github/copilot-instructions.md](.github/copilot-instructions.md)
- Project Homepage: [jmotools.com](https://jmotools.com)

## Document Creation Policy

**CRITICAL: Limit document creation and summaries unless they provide long-term project value.**

### When NOT to Create Documents

**Do NOT create markdown documents for:**

1. ❌ **Session summaries or task reports** — These are ephemeral and clutter the repository
2. ❌ **Temporary analysis notes** — Use conversation context instead
3. ❌ **Quick reference guides** — Information should go into existing docs
4. ❌ **One-off troubleshooting** — Document patterns in USER_GUIDE.md, not standalone files
5. ❌ **Work-in-progress drafts** — Keep in `.claude/` or `dev-only/` (gitignored)
6. ❌ **Review artifacts** — Use GitHub PR reviews, not committed files

**IMPORTANT .gitignore locations for temporary work:**

- **`.claude/`** — Claude Code user-specific configuration (gitignored in line 84)
- **`dev-only/`** — Private local scripts and outputs (gitignored in line 78)
- **`/tmp/`** — Test results and temporary files (gitignored in line 51)

**When temporary documents ARE needed:**

```bash
# Store drafts and analysis in gitignored locations
echo "analysis notes" > .claude/draft-analysis.md
echo "temp script" > dev-only/test-script.sh
echo "results" > /tmp/scan-output.json

# These files NEVER appear in git status
git status  # Clean working tree
```

### When to Create Documents

**ONLY create markdown documents when:**

1. ✅ **Long-term project value** — Information needed for >6 months
2. ✅ **User-facing documentation** — Guides, tutorials, references (see Perfect Documentation Structure below)
3. ✅ **Contributor onboarding** — CONTRIBUTING.md, TEST.md, RELEASE.md
4. ✅ **Architectural decisions** — Major design changes (CLAUDE.md, ROADMAP.md)
5. ✅ **Compliance/auditing** — Security policies, license info

**Examples of valid document creation:**

- Adding new section to USER_GUIDE.md for new CLI flag
- Creating docs/examples/new-workflow.md for reusable pattern
- Updating CHANGELOG.md for release notes
- Adding troubleshooting section to existing doc

### Document Management Workflow

**When documents ARE created, use the jmo-documentation-updater skill to manage them:**

```bash
# After creating or modifying documentation
# The skill will:
# 1. Check for duplicates and consolidate
# 2. Verify against Perfect Documentation Structure
# 3. Update docs/index.md with new links
# 4. Run markdownlint and fix ALL issues
# 5. Organize into appropriate locations
# 6. Archive or delete obsolete docs
```

**Invoke the skill:**

```text
Use the jmo-documentation-updater skill to:
- Organize new documentation about [topic]
- Check for duplicate content in [docs]
- Consolidate fragmented documentation
- Archive outdated [doc-name].md
```

**The skill ensures:**

- No duplicate content across files
- Proper linking in docs/index.md
- Compliance with Perfect Documentation Structure
- Markdownlint validation passes
- Proper .gitignore handling for drafts

### Prefer Editing Over Creating

**ALWAYS prefer editing existing files to creating new ones:**

```markdown
# ❌ WRONG: Create new SNYK_SETUP.md
echo "# Snyk Setup" > docs/SNYK_SETUP.md

# ✅ CORRECT: Add section to existing USER_GUIDE.md
# Edit docs/USER_GUIDE.md:
## Tool-Specific Configuration

### Snyk (SCA)
...
```

**Rationale:**

- **Reduced navigation:** Users know where to look (USER_GUIDE.md)
- **Easier maintenance:** One file to update, not scattered docs
- **Better search:** Ctrl+F finds everything in one place
- **No link rot:** Fewer files = fewer broken links

### Summary Guidelines

**Limit AI-generated summaries unless explicitly requested:**

- ❌ Don't create "SESSION_SUMMARY.md" after completing tasks
- ❌ Don't create "WORK_LOG.md" tracking daily progress
- ❌ Don't create "ANALYSIS_REPORT.md" for every investigation
- ✅ DO update CHANGELOG.md with user-facing changes
- ✅ DO add troubleshooting sections to USER_GUIDE.md
- ✅ DO document new patterns in docs/examples/

**If user requests a summary:**

1. **Provide in conversation** — Don't create a file unless explicitly requested
2. **Ask before creating** — "Should I add this to CHANGELOG.md or create a new doc?"
3. **Use .claude/ for drafts** — If unsure, put in `.claude/draft-summary.md` first
4. **Invoke jmo-documentation-updater** — After user approves, use skill to organize

## Perfect Documentation Structure

**IMPORTANT: This section defines the canonical documentation structure. Follow this guidance to avoid creating unnecessary or duplicate documentation files.**

### Documentation Hierarchy and Purpose

```text
/
├── README.md                          # Project overview, "Three Ways to Get Started", badges
├── QUICKSTART.md                      # 5-minute guide for all user types
├── CONTRIBUTING.md                    # Contributor setup and workflow
├── CHANGELOG.md                       # Version history with user-facing changes
├── ROADMAP.md                         # Future plans and completed milestones
├── SAMPLE_OUTPUTS.md                  # Example outputs from real scans
├── TEST.md                            # Testing guide for contributors
└── docs/
    ├── index.md                       # Documentation hub with all links
    ├── USER_GUIDE.md                  # Comprehensive reference guide
    ├── DOCKER_README.md               # Docker deep-dive (variants, CI/CD, troubleshooting)
    ├── docs/DOCKER_README.md # Complete beginner Docker tutorial
    ├── WIZARD_IMPLEMENTATION.md       # Wizard implementation details (for contributors)
    ├── RELEASE.md                     # Release process for maintainers
    ├── MCP_SETUP.md                   # MCP server setup instructions
    ├── examples/
    │   ├── README.md                  # Examples index
    │   ├── wizard-examples.md         # Wizard workflows and patterns
    │   ├── scan_from_tsv.md           # TSV scanning tutorial
    │   └── github-actions-docker.yml  # CI/CD examples
    ├── screenshots/
    │   └── README.md                  # Screenshot capture guide
    └── schemas/
        └── common_finding.v1.json     # CommonFinding data schema
```

### User Journey-Based Documentation

**Entry points based on user persona:**

1. **Complete Beginner** (Never used security tools)
   - Start: [docs/DOCKER_README.md#quick-start-absolute-beginners](docs/DOCKER_README.md#quick-start-absolute-beginners) OR run `jmotools wizard`
   - Reason: Zero-installation path with step-by-step guidance
   - Next: [docs/examples/wizard-examples.md](docs/examples/wizard-examples.md)

2. **Developer** (Familiar with CLI, wants quick start)
   - Start: [QUICKSTART.md](QUICKSTART.md)
   - Reason: Fast 5-minute setup with platform-specific instructions
   - Next: [docs/USER_GUIDE.md](docs/USER_GUIDE.md) for deeper features

3. **DevOps/SRE** (CI/CD integration focus)
   - Start: [docs/DOCKER_README.md](docs/DOCKER_README.md)
   - Reason: Container-based deployment, CI/CD patterns
   - Next: [docs/examples/github-actions-docker.yml](docs/examples/github-actions-docker.yml)

4. **Advanced User** (Fine-tuning, custom profiles)
   - Start: [docs/USER_GUIDE.md](docs/USER_GUIDE.md)
   - Reason: Comprehensive configuration reference
   - See also: `jmo.yml` examples and per-tool overrides

5. **Contributor** (Code contributions)
   - Start: [CONTRIBUTING.md](CONTRIBUTING.md)
   - Reason: Dev setup, coding standards, PR workflow
   - Next: [TEST.md](TEST.md) and [docs/RELEASE.md](docs/RELEASE.md)

### Documentation Content Guidelines

**README.md:**

- Purpose: First impression, project value proposition, quick navigation
- Content: Badges, "Three Ways to Get Started" (Wizard/Docker/Local), features overview, tool list
- Length: Moderate (current length is appropriate)
- Updates: When major features added (Docker, Wizard) or key workflows change

**QUICKSTART.md:**

- Purpose: Get ANY user from zero to first scan in 5 minutes
- Content: Platform-specific setup (Linux/WSL/macOS), basic scan commands, result viewing
- Length: Concise, scannable
- Updates: When default workflows or commands change

**docs/USER_GUIDE.md:**

- Purpose: Comprehensive reference for all features
- Content: Configuration reference, CLI synopsis, profiles, suppressions, CI troubleshooting
- Length: Long (current length appropriate)
- Updates: When new CLI flags, config options, or features added

**docs/DOCKER_README.md:**

- Purpose: Complete Docker guide for all skill levels
- Content: Image variants, CI/CD patterns, troubleshooting, security considerations
- Length: Medium-long
- Updates: When new Docker images, variants, or CI examples added

**docs/DOCKER_README.md#quick-start-absolute-beginners:**

- Purpose: Hand-holding tutorial for absolute beginners
- Content: Docker installation, first scan, understanding results, common scenarios
- Length: Long (step-by-step requires detail)
- Updates: When beginner workflows or Docker commands change

**docs/examples/wizard-examples.md:**

- Purpose: Wizard workflows and use cases
- Content: Interactive mode, non-interactive mode, artifact generation, common patterns
- Length: Medium
- Updates: When wizard features or flags added

**docs/index.md:**

- Purpose: Documentation hub - single source of truth for all doc links
- Content: Links to all docs organized by purpose, quick links, FAQ
- Length: Short (just navigation)
- Updates: When ANY documentation file is added, moved, or removed

### What NOT to Create

**Do NOT create these files unless explicitly requested:**

1. ❌ `ARCHITECTURE.md` - Architecture covered in CLAUDE.md
2. ❌ `INSTALLATION.md` - Installation covered in QUICKSTART.md and README.md
3. ❌ `CONFIGURATION.md` - Configuration covered in USER_GUIDE.md
4. ❌ `API.md` - Not applicable (CLI tool, not library)
5. ❌ `TUTORIAL.md` - Tutorials split appropriately (Docker beginner, Wizard examples)
6. ❌ `FAQ.md` - FAQ embedded in docs/index.md and relevant guides
7. ❌ `DEVELOPMENT.md` - Development covered in CONTRIBUTING.md
8. ❌ Additional `ROADMAP_*.md` files - Single ROADMAP.md is sufficient
9. ❌ Multiple beginner guides - One comprehensive Docker guide is enough
10. ❌ Duplicate quick starts - QUICKSTART.md is the canonical 5-minute guide

### Documentation Update Triggers

**When to update documentation:**

1. **New Major Feature** (Docker images, Wizard, etc.)
   - Update: README.md, QUICKSTART.md, docs/index.md, relevant deep-dive docs
   - Add: Examples in docs/examples/ if workflow patterns emerge
   - Update: CHANGELOG.md with user-facing changes

2. **New CLI Flag or Command**
   - Update: docs/USER_GUIDE.md (CLI synopsis section)
   - Update: QUICKSTART.md if it affects basic workflows
   - Update: docs/examples/ if it enables new patterns

3. **New Configuration Option**
   - Update: docs/USER_GUIDE.md (Configuration section)
   - Update: Example `jmo.yml` snippets throughout docs
   - Update: docs/index.md FAQ if commonly asked

4. **Breaking Change**
   - Update: ALL affected documentation files
   - Add: Migration guide in CHANGELOG.md
   - Add: Deprecation notices in relevant docs

5. **Bug Fix (User-Facing)**
   - Update: CHANGELOG.md only
   - Update: Troubleshooting sections if behavior change affects common issues

6. **Contributor Workflow Change**
   - Update: CONTRIBUTING.md, TEST.md, docs/RELEASE.md
   - Update: CLAUDE.md if dev setup changes

### Documentation Cross-References

**Always use relative links:**

- ✅ `[docs/USER_GUIDE.md](docs/USER_GUIDE.md)`
- ❌ `https://github.com/jimmy058910/jmo-security-repo/blob/main/docs/USER_GUIDE.md` (breaks in forks)

**Link to section anchors when helpful:**

- ✅ `[USER_GUIDE.md — Configuration](docs/USER_GUIDE.md#configuration-jmoyml)`
- ✅ `[QUICKSTART.md — Docker Mode](QUICKSTART.md#docker-mode)`

**Maintain bi-directional links:**

- README.md → QUICKSTART.md → USER_GUIDE.md → docs/examples/
- Each doc should link back to docs/index.md or README.md

### Documentation Maintenance Checklist

When adding/updating documentation:

- [ ] Updated docs/index.md with new links
- [ ] Updated CHANGELOG.md if user-facing
- [ ] Verified all cross-references still work
- [ ] Checked for duplicate content (consolidate if found)
- [ ] Used relative links (no absolute GitHub URLs)
- [ ] Added section to table of contents if new doc
- [ ] Ran markdownlint (`make pre-commit-run`)
- [ ] Verified examples are copy-pasteable
- [ ] Updated CLAUDE.md if documentation structure changed

## Key Files Reference

| File | Purpose |
|------|---------|
| `scripts/cli/jmo.py` | Main CLI entry point (scan/report/ci) |
| `scripts/cli/jmotools.py` | Wrapper commands (wizard, fast, balanced, full, setup) |
| `scripts/cli/wizard.py` | Interactive wizard implementation |
| `scripts/core/normalize_and_report.py` | Aggregation engine, deduplication, enrichment |
| `scripts/core/config.py` | Config loader for jmo.yml |
| `scripts/core/common_finding.py` | CommonFinding schema and fingerprinting |
| `scripts/core/adapters/*.py` | Tool output parsers |
| `scripts/core/reporters/*.py` | Output formatters (JSON/MD/YAML/HTML/SARIF) |
| `scripts/dev/update_versions.py` | **Version management automation (v0.6.1+)** |
| `jmo.yml` | Main configuration file |
| `versions.yaml` | **Central tool version registry (v0.6.1+)** |
| `pyproject.toml` | Python package metadata and build config |
| `Makefile` | Developer shortcuts for common tasks |
| `Dockerfile`, `Dockerfile.slim`, `Dockerfile.alpine` | Docker image variants |
| `.pre-commit-config.yaml` | Pre-commit hook configuration |
| `.github/workflows/ci.yml` | Primary CI: tests, quick checks, nightly lint |
| `.github/workflows/release.yml` | Release automation: PyPI + Docker builds |
| `.github/workflows/version-check.yml` | **Weekly version consistency checks (v0.6.1+)** |
| `.github/dependabot.yml` | **Automated dependency updates (v0.6.1+)** |
