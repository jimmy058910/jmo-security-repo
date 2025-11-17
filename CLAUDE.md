# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

JMo Security Audit Tool Suite is a terminal-first, cross-platform security audit toolkit that orchestrates multiple scanners with a unified Python CLI, normalized outputs, and an HTML dashboard. The project scans repositories for secrets, vulnerabilities, misconfigurations, and security issues using industry-standard tools.

**Current Version:** v1.0.0 (production release)

**Key Philosophy:**

- Two-phase architecture: **scan** (invoke tools, write raw JSON) → **report** (normalize, dedupe, emit unified outputs)
- Unified CommonFinding schema with stable fingerprinting for deduplication
- Profile-based configuration for different scan depths (fast/balanced/deep)
- **SQLite historical storage** for trend analysis and security posture tracking (v1.0.0)
- **Machine-readable diffs** for regression detection and PR reviews (v1.0.0)
- **Statistical trend analysis** with Mann-Kendall validation (v1.0.0)
- **SQLite historical storage** for trend analysis and security posture tracking (v1.0.0)
- **Machine-readable diffs** for regression detection and PR reviews (v1.0.0)
- **Statistical trend analysis** with Mann-Kendall validation (v1.0.0)
- Resilient to missing tools with fallback mechanisms

## v1.0.0 Production Release

**Status:** 🎉 **Production Ready** (Release Score: 92/100)

### Core Features (Production)

- ✅ **SQLite Historical Storage:** 13 CLI commands for scan history and trend tracking
- ✅ **Machine-Readable Diffs:** 4 output formats (JSON, Markdown, HTML, SARIF) for regression detection
- ✅ **Statistical Trend Analysis:** Mann-Kendall validation, 8 trend commands, security posture scoring
- ✅ **Cross-Tool Deduplication:** 30-40% noise reduction via similarity clustering
- ✅ **Output Format Standardization:** v1.0.0 metadata wrapper, CSV export, dual-mode HTML
- ✅ **28 Security Scanners:** Unified adapter architecture with plugin system
- ✅ **SLSA Attestation:** Supply chain security with cryptographic signatures
- ✅ **Policy-as-Code:** Compliance enforcement with 6 framework mappings

### Test Coverage

- **2,981 automated tests** (99.97% pass rate)
- **87% code coverage** (exceeds 85% CI requirement)
- **Performance validated:** <50ms scan insert, <200ms trend analysis
- **Multi-platform:** Ubuntu, macOS, WSL2 compatibility verified

### Ongoing Enhancements (Post-v1.0.0)

Future releases will include profile enhancements, advanced filtering, CI/CD templates, and performance optimizations. See [dev-only/1.0.0/STATUS.md](dev-only/1.0.0/STATUS.md) for roadmap.

## Core Commands

### Development Setup

```bash
## Install Python dev dependencies
make dev-deps

## Install pre-commit hooks (YAML/Actions validation, formatting, linting)
make pre-commit-install

## Install external security tools (semgrep, trivy, checkov, etc.)
make tools

## Verify environment and tool availability
make verify-env

## Format code (shfmt, black, ruff)
make fmt

## Lint code (shellcheck, ruff, bandit, pre-commit)
make lint

## Run tests with coverage (CI requires ≥85%)
make test

```

### Dependency Management

```bash
## Compile requirements-dev.in → requirements-dev.txt (pip-tools)
make deps-compile

## Sync environment to compiled requirements
make deps-sync

## Upgrade pip/setuptools/wheel
make upgrade-pip

## Alternative: use uv for faster compilation/sync
make uv-sync

```

### Version Management (v0.6.1+)

**IMPORTANT: Use the 5-layer version management system to update tool versions.**

```bash
## Check current versions
python3 scripts/dev/update_versions.py --report

## Check for available updates
python3 scripts/dev/update_versions.py --check-latest

## Update a specific tool
python3 scripts/dev/update_versions.py --tool trivy --version 0.68.0

## Sync all Dockerfiles with versions.yaml
python3 scripts/dev/update_versions.py --sync

## Validate consistency (CI uses this)
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

**See [docs/VERSION_MANAGEMENT.md](docs/VERSION_MANAGEMENT.md) for complete documentation.**

### Running Scans

```bash
## Interactive wizard (recommended for first-time users)
jmo wizard

## Non-interactive wizard with defaults
jmo wizard --yes

## Fast scan with profile
jmo scan --repos-dir ~/repos --profile-name fast

## Balanced scan (default profile)
jmo scan --repos-dir ~/repos --profile-name balanced

## Full deep scan
jmo scan --repos-dir ~/repos --profile-name deep

## Multi-target scanning (v0.6.0+)
## Scan container images
jmo scan --image nginx:latest --tools trivy syft

## Scan IaC files
jmo scan --terraform-state infrastructure.tfstate --tools checkov trivy

## Scan live web URLs (DAST)
jmo scan --url https://example.com --tools zap

## Scan GitLab repositories
jmo scan --gitlab-repo mygroup/myrepo --gitlab-token TOKEN --tools trufflehog

## Scan Kubernetes clusters
jmo scan --k8s-context prod --k8s-all-namespaces --tools trivy

## Scan multiple target types in one command
jmo scan \
  --repo ./myapp \
  --image myapp:latest \
  --terraform-state infrastructure.tfstate \
  --url https://myapp.com \
  --gitlab-repo myorg/backend \
  --k8s-context prod \
  --results-dir ./comprehensive-audit

## Aggregate and report (all target types)
jmo report ./results --profile --human-logs

## CI mode: scan + report + threshold gating (multi-target support)
jmo ci --image nginx:latest --url https://api.example.com --fail-on HIGH --profile

```

### Historical Storage & Trend Analysis (v1.0.0)

**SQLite-based historical tracking for security posture monitoring:**

```bash
## List all historical scans
jmo history list

## Show detailed scan information
jmo history show SCAN_ID

## Compare two scans (diff + statistics)
jmo history compare SCAN1_ID SCAN2_ID

## Export scan history to JSON
jmo history export --output scans.json

## Prune old scans (keep last N)
jmo history prune --keep 50

## Database maintenance
jmo history vacuum
jmo history verify

## Trend analysis with statistical validation
jmo trends analyze --days 30
jmo trends regressions --threshold 10
jmo trends score  # Security posture score (0-100)
jmo trends compare --baseline SCAN_ID
jmo trends insights --period week

## Developer attribution tracking
jmo trends developers --top 10
jmo trends explain --finding-id FINGERPRINT

## Export formats (JSON, HTML, CSV, Prometheus, Grafana, Dashboard)
jmo trends analyze --export-json trends.json
jmo trends analyze --export-html trends.html
jmo trends analyze --export-csv trends.csv
jmo trends analyze --export-prometheus metrics.prom
jmo trends analyze --export-grafana dashboard.json
jmo trends analyze --export-dashboard data.json

```

**Performance Benchmarks:**

- Single scan insert: <50ms
- History list (10k scans): <100ms
- Trend analysis (30 days): <200ms
- Statistical validation: Mann-Kendall test (p < 0.05 significance)

**Docker Volume Mounting (CRITICAL):**

```bash
## MUST mount .jmo/history.db for persistence
docker run --rm \
  -v $PWD:/scan \
  -v $PWD/.jmo/history.db:/scan/.jmo/history.db \
  -v $PWD/results:/results \
  jmo-security:latest scan --repo /scan

```

### Machine-Readable Diffs (v1.0.0)

**Compare scans to detect regressions, track remediation, automate PR reviews:**

```bash
## Compare two result directories
jmo diff results-baseline/ results-current/

## Filter by severity
jmo diff results-baseline/ results-current/ --severity HIGH CRITICAL

## Show only new findings
jmo diff results-baseline/ results-current/ --only new

## Generate PR comment (Markdown)
jmo diff results-baseline/ results-current/ --format md > pr-comment.md

## Interactive HTML report
jmo diff results-baseline/ results-current/ --format html

## SARIF 2.1.0 diff format
jmo diff results-baseline/ results-current/ --format sarif

## SQLite-based historical comparison
jmo diff --scan-id BASELINE_ID --scan-id CURRENT_ID

```

**Four Output Formats:**

1. **JSON (v1.0.0)** — Machine-readable with metadata envelope
2. **Markdown** — PR/MR comment automation
3. **HTML** — Interactive dashboard with filters
4. **SARIF 2.1.0** — Code scanning platforms integration

**CI/CD Integration Examples:**

- GitHub Actions: Post diff as PR comment
- GitLab CI: Create MR notes with remediation tracking
- Performance: <500ms for 1000-finding diffs

```bash
## List all historical scans
jmo history list

## Show detailed scan information
jmo history show SCAN_ID

## Compare two scans (diff + statistics)
jmo history compare SCAN1_ID SCAN2_ID

## Export scan history to JSON
jmo history export --output scans.json

## Prune old scans (keep last N)
jmo history prune --keep 50

## Database maintenance
jmo history vacuum
jmo history verify

## Trend analysis with statistical validation
jmo trends analyze --days 30
jmo trends regressions --threshold 10
jmo trends score  ## Security posture score (0-100)
jmo trends compare --baseline SCAN_ID
jmo trends insights --period week

## Developer attribution tracking
jmo trends developers --top 10
jmo trends explain --finding-id FINGERPRINT

## Export formats (JSON, HTML, CSV, Prometheus, Grafana, Dashboard)
jmo trends analyze --export-json trends.json
jmo trends analyze --export-html trends.html
jmo trends analyze --export-csv trends.csv
jmo trends analyze --export-prometheus metrics.prom
jmo trends analyze --export-grafana dashboard.json
jmo trends analyze --export-dashboard data.json
```

**Performance Benchmarks:**

- Single scan insert: <50ms
- History list (10k scans): <100ms
- Trend analysis (30 days): <200ms
- Statistical validation: Mann-Kendall test (p < 0.05 significance)

**Docker Volume Mounting (CRITICAL):**

```bash
## MUST mount .jmo/history.db for persistence
docker run --rm \
  -v $PWD:/scan \
  -v $PWD/.jmo/history.db:/scan/.jmo/history.db \
  -v $PWD/results:/results \
  jmo-security:latest scan --repo /scan

```

```bash
## Compare two result directories
jmo diff results-baseline/ results-current/

## Filter by severity
jmo diff results-baseline/ results-current/ --severity HIGH CRITICAL

## Show only new findings
jmo diff results-baseline/ results-current/ --only new

## Generate PR comment (Markdown)
jmo diff results-baseline/ results-current/ --format md > pr-comment.md

## Interactive HTML report
jmo diff results-baseline/ results-current/ --format html

## SARIF 2.1.0 diff format
jmo diff results-baseline/ results-current/ --format sarif

## SQLite-based historical comparison
jmo diff --scan-id BASELINE_ID --scan-id CURRENT_ID
```

**Four Output Formats:**

1. **JSON (v1.0.0)** — Machine-readable with metadata envelope
2. **Markdown** — PR/MR comment automation
3. **HTML** — Interactive dashboard with filters
4. **SARIF 2.1.0** — Code scanning platforms integration

**CI/CD Integration Examples:**

- GitHub Actions: Post diff as PR comment
- GitLab CI: Create MR notes with remediation tracking
- Performance: <500ms for 1000-finding diffs

### Running a Single Test

```bash
## Run specific test file
pytest tests/unit/test_common_and_sarif.py -v

## Run specific test function
pytest tests/unit/test_common_and_sarif.py::test_write_sarif -v

## Run with coverage
pytest tests/unit/ --cov=scripts --cov-report=term-missing

## Run adapter tests (useful when adding new tool adapters)
pytest tests/adapters/test_gitleaks_adapter.py -v

## Run integration tests (end-to-end CLI workflows)
pytest tests/integration/test_cli_scan_ci.py -v

## Run tests by category
pytest tests/unit/ -v         # All unit tests
pytest tests/adapters/ -v     # All adapter tests
pytest tests/reporters/ -v    # All reporter tests
pytest tests/integration/ -v  # All integration tests

## Run v1.0.0 feature tests
pytest tests/unit/test_history_db.py -v       # SQLite storage
pytest tests/unit/test_diff_engine.py -v      # Diff engine
pytest tests/unit/test_trend_analyzer.py -v   # Trend analysis

```

## Architecture

### Directory Structure

```text
scripts/
├── cli/
│   ├── jmo.py                    # Main CLI entry point (scan/report/ci/diff/history/trends)
│   ├── scan_orchestrator.py     # v0.9.0: Refactored scan orchestration
│   ├── report_orchestrator.py   # v0.9.0: Refactored report orchestration
│   ├── ci_orchestrator.py       # v0.9.0: Refactored CI orchestration
│   ├── diff_commands.py         # v1.0.0: Diff CLI commands
│   ├── history_commands.py      # v1.0.0: Historical storage CLI
│   ├── trend_commands.py        # v1.0.0: Trend analysis CLI
│   ├── schedule_commands.py     # v0.9.0: Scheduled scan management
│   ├── wizard_flows/            # v0.9.0: Refactored wizard modules
│   │   ├── base_flow.py         # Core wizard orchestration
│   │   ├── target_configurators.py  # Target selection flows
│   │   ├── cicd_flow.py         # CI/CD artifact generation
│   │   └── ...
│   └── scan_jobs/               # v0.9.0: Scanner implementations
│       ├── base_scanner.py      # Abstract scanner base
│       ├── repository_scanner.py
│       ├── image_scanner.py
│       ├── iac_scanner.py
│       ├── url_scanner.py
│       ├── gitlab_scanner.py
│       └── k8s_scanner.py
├── core/
│   ├── normalize_and_report.py  # Aggregation engine: loads tool outputs, dedupes, enriches
│   ├── config.py                # Config loader for jmo.yml
│   ├── suppress.py              # Suppression logic (jmo.suppress.yml)
│   ├── common_finding.py        # CommonFinding schema and fingerprinting
│   ├── history_db.py            # v1.0.0: SQLite historical storage
│   ├── diff_engine.py           # v1.0.0: Diff computation engine
│   ├── trend_analyzer.py        # v1.0.0: Statistical trend analysis
│   ├── developer_attribution.py # v1.0.0: Git blame-based attribution
│   ├── epss_integration.py      # v0.9.0: EPSS risk scoring
│   ├── kev_integration.py       # v0.9.0: CISA KEV catalog
│   ├── email_service.py         # v0.9.0: Email notifications
│   ├── cron_installer.py        # v0.9.0: Scheduled scans
│   ├── telemetry.py             # v0.9.0: Anonymous usage metrics
│   ├── adapters/                # Tool output parsers
│   │   ├── gitleaks_adapter.py
│   │   ├── semgrep_adapter.py
│   │   ├── trivy_adapter.py
│   │   └── ...
│   └── reporters/               # Output formatters
│       ├── basic_reporter.py    # JSON + Markdown (v1.0.0 metadata wrapper)
│       ├── yaml_reporter.py     # YAML (v1.0.0 metadata wrapper)
│       ├── html_reporter.py     # Interactive dashboard (v1.0.0 dual-mode)
│       ├── sarif_reporter.py    # SARIF 2.1.0
│       ├── csv_reporter.py      # v1.0.0: CSV export
│       ├── diff_json_reporter.py    # v1.0.0: Diff JSON output
│       ├── diff_md_reporter.py      # v1.0.0: Diff Markdown (PR comments)
│       ├── diff_html_reporter.py    # v1.0.0: Diff HTML dashboard
│       ├── diff_sarif_reporter.py   # v1.0.0: SARIF diff format
│       └── suppression_reporter.py  # Suppression summary
└── dev/                         # Helper scripts for tool installation and CI

tests/
├── unit/                        # Core logic tests
├── adapters/                    # Adapter tests with fabricated JSON fixtures
├── reporters/                   # Reporter tests
├── integration/                 # End-to-end CLI tests
└── cli/                         # CLI argument and smoke tests

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
   - **v1.0.0:** Auto-stores scan to SQLite history database (`.jmo/history.db`)

2. **Report Phase** (`jmo report`):
   - Scans all 6 target type directories for tool outputs
   - Loads all tool outputs via adapters
   - Normalizes to CommonFinding schema (v1.2.0 with compliance fields)
   - Deduplicates by fingerprint ID across all target types
   - Enriches findings with compliance frameworks (OWASP, CWE, CIS, NIST CSF, PCI DSS, ATT&CK)
   - **v0.9.0:** Enriches with EPSS risk scores and CISA KEV catalog
   - Enriches Trivy findings with Syft SBOM context
   - **v1.0.0:** Writes unified outputs with metadata envelope wrapper
   - **v1.0.0:** Supports severity-based failure thresholds (`--fail-on HIGH`)

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
- **EPSS field (v0.9.0+):** `epss` object with score, percentile (for CVEs)
- **KEV field (v0.9.0+):** `kev` boolean indicating CISA Known Exploited Vulnerability
- **Fingerprinting:** Deterministic ID computed from `tool | ruleId | path | startLine | message[:120]` to enable cross-run deduplication
- **Schema Versions:**
  - **1.0.0:** Basic finding format
  - **1.1.0:** Added `risk`, `context`, enhanced remediation
  - **1.2.0:** Added `compliance` field (v0.5.1+), auto-enriched during reporting

**v1.0.0 Metadata Wrapper:**

All output formats now include a metadata envelope for machine-parseable context:

```json
{
  "meta": {
    "output_version": "1.0.0",
    "jmo_version": "0.9.0",
    "schema_version": "1.2.0",
    "timestamp": "2025-11-05T12:34:56Z",
    "scan_id": "abc123...",
    "profile": "balanced",
    "tools": ["trivy", "semgrep", "trufflehog"],
    "target_count": 5,
    "finding_count": 42,
    "platform": {"os": "linux", "python": "3.11.0"}
  },
  "findings": [
    {
      "schemaVersion": "1.2.0",
      "id": "fingerprint-abc123",
      ...
    }
  ]
}

```

**Impact:**

- Version tracking: Know which JMo version produced results
- Full scan context: Profile, tools, targets in metadata
- Machine-parseable: CI/CD pipelines can parse metadata
- Backward compatibility: Access findings via `.findings` field

**Cross-Tool Deduplication (v1.0.0):**

JMo Security implements a two-phase deduplication architecture to eliminate noise from duplicate findings:

1. **Phase 1: Fingerprint Deduplication (Existing)**
   - Deterministic fingerprint IDs: `SHA256(tool | ruleId | path | startLine | message[:120])`
   - Removes exact duplicates from same tool, same location
   - O(n) time complexity using dictionary lookup

2. **Phase 2: Similarity Clustering (v1.0.0)**
   - Multi-dimensional similarity matching across tools
   - Three-component algorithm with weighted scores:
     - **Location (35%):** Path normalization + line range overlap (Jaccard index + gap penalty)
     - **Message (40%):** Hybrid fuzzy + token matching (rapidfuzz + security keyword extraction)
     - **Metadata (25%):** CWE/CVE/Rule ID family matching
   - **Threshold:** 0.75 similarity required for clustering (Goldilocks zone: 85%+ accuracy, minimal false positives)
   - **Type conflict detection:** Halves similarity score if CWEs differ or CVE vs code issue mismatch
   - **Greedy clustering:** O(n×k) where k = avg cluster size (~3-5 tools per finding)
   - **Performance:** <2 seconds for 1000 findings

**Consensus Finding Generation:**

When multiple tools detect the same issue, JMo creates a single consensus finding:

- **Representative:** Highest-severity finding becomes primary
- **detected_by:** Array of tool objects with name/version
- **Confidence levels:**
  - HIGH: 4+ tools agree (very likely true positive)
  - MEDIUM: 2-3 tools agree (likely true positive)
  - LOW: Single tool (requires validation)
- **Duplicates:** Non-representative findings stored in `context.duplicates` with similarity scores
- **Severity elevation:** Elevated to highest severity in cluster (e.g., HIGH + MEDIUM → HIGH)

**Configuration:**

```yaml
# jmo.yml
deduplication:
  cross_tool_clustering: true  # Enable/disable (default: true)
  similarity_threshold: 0.75   # Clustering strictness (0.70-0.85)

  # Optional: Custom component weights (must sum to 1.0)
  location_weight: 0.35
  message_weight: 0.40
  metadata_weight: 0.25
```

**Impact:**

- 30-40% reduction in reported findings (noise elimination)
- ≥85% clustering accuracy (validated on 200+ finding sample)
- <2 seconds clustering time for 1000 findings
- Zero breaking changes (consensus findings are valid CommonFinding v1.2.0 objects)

**Implementation Files:**

- `scripts/core/dedup_enhanced.py` — Clustering engine (SimilarityCalculator, FindingClusterer)
- `scripts/core/normalize_and_report.py` — Integration point (_cluster_cross_tool_duplicates)
- `tests/unit/test_dedup_enhanced.py` — Comprehensive test suite (38/38 tests passing)
- `tests/integration/test_cross_tool_dedup_integration.py` — End-to-end integration tests (3/3 passing)

**Profiles (v0.5.0):**

Configuration via `jmo.yml` supports named profiles for different scan depths:

- **fast:** 8 core tools (trufflehog, semgrep, trivy, checkov, checkov-cicd, hadolint, syft, osv-scanner), 300s timeout, 8 threads, 5-10 minutes
  - Use case: Pre-commit checks, quick validation, CI/CD gate
  - Coverage: Verified secrets, SAST, SCA, containers, IaC, Dockerfile, backup secrets scanning

- **balanced:** 21 production tools (fast tools + prowler, kubescape, zap, nuclei, akto, cdxgen, scancode, gosec, grype, yara, bearer, horusec, dependency-check), 600s timeout, 4 threads, 18-25 minutes
  - Use case: CI/CD pipelines, regular audits, production scans
  - Coverage: All fast + cloud CSPM, DAST, API security, SBOM expansion, malware detection, license compliance

- **deep:** 28 comprehensive tools (all tools including noseyparker, semgrep-secrets, bandit, trivy-rbac, falco, afl++, mobsf, lynis), 900s timeout, 2 threads, 40-70 minutes, retries enabled
  - Use case: Security audits, compliance scans, pre-release validation
  - Coverage: Dual secrets scanners, multi-language SAST, full SBOM, cloud/K8s hardening, mobile security, system hardening, runtime security, fuzzing

Profiles can override tools, timeouts, threads, and per-tool flags. Use `--profile-name <name>` to apply.

**Interactive Wizard:**

The wizard (`jmo wizard`) provides guided onboarding for first-time users:

- **Interactive mode:** Step-by-step prompts for profile selection, target configuration, execution mode (Docker/native)
- **Non-interactive mode:** `--yes` flag uses smart defaults for automation
- **Artifact generation:** Can emit Makefile targets (`--emit-make-target`), shell scripts (`--emit-script`), or GitHub Actions workflows (`--emit-gha`) for reusable configurations
- **Docker integration:** Automatically detects Docker availability and offers zero-installation scanning
- **v1.0.0:** Post-scan prompts for trend analysis, diff generation, historical comparison
- Auto-opens results dashboard after scan completion

**SQLite Historical Storage (v1.0.0):**

All scans are automatically stored in `.jmo/history.db` for trend analysis:

- **Schema:** 3 tables (scans, findings, trends)
- **Scan metadata:** Git context (commit, branch, tag), configuration (profile, tools), summary counts
- **Fingerprint-based deduplication:** Findings tracked across scans via stable IDs
- **Performance:** <100ms queries for 10k findings, connection pooling, indexed queries
- **Database location:** `.jmo/history.db` (configurable via `--db-path`)
- **Docker requirement:** MUST mount volume for persistence (`-v $PWD/.jmo:/scan/.jmo`)

**Machine-Readable Diffs (v1.0.0):**

DiffEngine provides fingerprint-based comparison for regression detection:

- **Algorithm:** O(n) set-based diff using fingerprint IDs
- **Categories:** New findings, fixed findings, modified findings (severity/compliance changes)
- **Filtering:** By severity, tool, category, or combination
- **Four output formats:** JSON (v1.0.0), Markdown (PR comments), HTML (interactive), SARIF 2.1.0
- **Two comparison modes:**
  - **Directory mode (primary):** Compare `results-A/` vs `results-B/`
  - **SQLite mode:** Compare historical scans via `--scan-id`
- **Performance:** <500ms for 1000-finding diffs, <2s for 10K-finding diffs
- **CI/CD integration:** GitHub Actions, GitLab CI, Jenkins examples

**Trend Analysis (v1.0.0):**

Statistical trend detection with Mann-Kendall validation:

- **Statistical rigor:** Mann-Kendall test (p < 0.05 significance threshold)
- **Security scoring:** 0-100 scale with letter grades (A-F)
  - Formula: `100 - (critical×10) - (high×3) - (medium×1)`
  - Thresholds: A (90-100), B (80-89), C (70-79), D (60-69), F (<60)
- **Developer attribution:** Git blame-based remediation tracking per developer/team
- **Export formats:** JSON (React apps), HTML (interactive reports), CSV (Excel), Prometheus (monitoring), Grafana (dashboards), Dashboard (optimized JSON)
- **Eight commands:**
  - `analyze`: Overall trend analysis with statistical validation
  - `show`: Detailed trend visualization
  - `regressions`: Detect security regressions (threshold-based)
  - `score`: Security posture score calculation
  - `compare`: Compare against baseline scan
  - `insights`: Actionable insights (weekly/monthly/quarterly)
  - `explain`: Explain finding lifecycle
  - `developers`: Developer velocity tracking
- **Performance:** <100ms for 50 scans, <500ms for 200 scans

### Tool Adapters

Each adapter in `scripts/core/adapters/` follows this pattern:

1. Check if output file exists
2. Parse tool-specific JSON format
3. Map to CommonFinding schema
4. Generate stable fingerprint ID
5. Return list of findings

**Supported Tools (v1.0.0):**

- **Secrets:** trufflehog (verified, 95% false positive reduction), noseyparker (optional, deep profile), semgrep-secrets
- **SAST:** semgrep (multi-language), bandit (Python-specific), gosec (Go security), horusec (multi-language)
- **SBOM+Vuln:** syft (SBOM generation), trivy (vuln/misconfig/secrets scanning), grype (Anchore vulnerability scanner), osv-scanner (Google OSV database), dependency-check (OWASP Dependency-Check)
- **IaC:** checkov (policy-as-code), checkov-cicd (CI/CD pipeline security)
- **Dockerfile:** hadolint (best practices)
- **DAST:** OWASP ZAP (web security, runtime vulnerabilities), Nuclei (fast vulnerability scanner with 4000+ templates), Akto (API security testing)
- **Cloud CSPM:** Prowler (AWS/Azure/GCP/K8s security auditing), Kubescape (Kubernetes security scanner)
- **Mobile Security:** MobSF (Android/iOS static/dynamic analysis, manual install)
- **Malware Detection:** YARA (malware pattern matching)
- **System Hardening:** Lynis (Unix system security auditing)
- **Runtime Security:** Falco (container/K8s monitoring, eBPF-based, deep profile), Trivy-RBAC (Kubernetes RBAC scanner)
- **Fuzzing:** AFL++ (coverage-guided fuzzing, deep profile)
- **License Compliance:** Bearer (security/privacy scanner), ScanCode (license compliance)

**Tool Count: 28 security scanners** (26 Docker-ready: trufflehog, noseyparker, semgrep, semgrep-secrets, bandit, syft, trivy, trivy-rbac, checkov, checkov-cicd, hadolint, zap, nuclei, prowler, kubescape, scancode, cdxgen, gosec, osv-scanner, yara, grype, bearer, horusec, dependency-check, falco, afl++; 2 manual install: mobsf, akto)

**Removed Tools (v0.5.0):**

- ❌ gitleaks → Replaced by trufflehog (better verification, fewer false positives)
- ❌ tfsec → Deprecated since 2021, functionality merged into trivy
- ❌ osv-scanner → Trivy provides superior container/dependency scanning

**Nosey Parker Fallback:**

When local binary is missing/fails, automatically falls back to Docker-based runner via `scripts/core/run_noseyparker_docker.sh`. Requires Docker installed and `ghcr.io/praetorian-inc/noseyparker:latest` image.

### Plugin Architecture (v0.9.0+)

**All tool adapters use a plugin architecture introduced in v0.9.0** for faster development, independent updates, and hot-reload during development.

**Key Benefits:**

- ✅ **Faster tool integration:** 4 hours → 1 hour per adapter (75% reduction)
- ✅ **Independent adapter updates:** Ship adapter improvements without core releases
- ✅ **Hot-reload during development:** No reinstall needed when editing adapters
- ✅ **Low-risk experimentation:** Test new tools without committing to codebase
- ✅ **Dynamic discovery:** Adapters auto-discovered from multiple search paths

**Plugin System Components:**

1. **[plugin_api.py](scripts/core/plugin_api.py)** — Base classes and decorators
   - `Finding` dataclass (CommonFinding schema v1.2.0)
   - `PluginMetadata` dataclass (name, version, author, description, tool_name, schema_version, output_format, exit_codes)
   - `AdapterPlugin` abstract base class
   - `@adapter_plugin` decorator for registration
   - Default `get_fingerprint()` implementation

2. **[plugin_loader.py](scripts/core/plugin_loader.py)** — Auto-discovery and loading
   - `PluginRegistry` class (register/get/list/unregister plugins)
   - `PluginLoader` class (auto-discovery from search paths, hot-reload)
   - Global singleton functions: `discover_adapters()`, `get_plugin_registry()`, `get_plugin_loader()`

3. **[normalize_and_report.py](scripts/core/normalize_and_report.py)** — Integration point
   - Dynamically discovers adapters via `discover_adapters()`
   - Loads tool outputs using plugin registry
   - No hard-coded imports or tool lists

**Search Paths:**

- `~/.jmo/adapters/` — User plugins (highest priority, for custom adapters)
- `scripts/core/adapters/` — Built-in plugins (12 official adapters)

**Creating a New Adapter:**

See [.claude/skills/jmo-adapter-generator/SKILL.md](.claude/skills/jmo-adapter-generator/SKILL.md) for complete step-by-step guide.

**Quick Example:**

```python
@adapter_plugin(PluginMetadata(
    name="mytool",  # CRITICAL: Must match mytool.json filename
    version="1.0.0",
    tool_name="mytool",
    schema_version="1.2.0"
))
class MyToolAdapter(AdapterPlugin):
    @property
    def metadata(self):
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path) -> List[Finding]:
        # Parse tool output, create Finding objects, return list
        findings = []
        # ... parsing logic ...
        return findings

```

**Key Requirements:**

1. **Plugin name MUST match JSON filename:** `mytool.json` → `name="mytool"`
2. **Special case:** `afl++.json` → use `name="aflplusplus"` (handled automatically)
3. **Direct Finding creation:** Create `Finding` objects, not dicts
4. **Compliance enrichment:** Use dict conversion pattern (see reference implementations)

**Hot-Reload During Development:**

```bash
## Edit adapter (no reinstall needed)
vim scripts/core/adapters/trivy_adapter.py

## Run tests immediately - plugin auto-reloads
pytest tests/adapters/test_trivy_adapter.py -v

```

**CLI Commands for Plugin Management (v0.9.0+):**

```bash
## List all loaded plugins
jmo adapters list
## Output:
## Loaded 12 adapter plugins:
##   trivy           v1.0.0    Adapter for Aqua Security Trivy vulnerability scanner
##   semgrep         v1.0.0    Adapter for Semgrep multi-language SAST scanner
##   ...

## Validate a plugin file
jmo adapters validate scripts/core/adapters/mytool_adapter.py
## Output: ✅ Valid plugin: scripts/core/adapters/mytool_adapter.py

```

**Testing Adapters:**

```bash
## Test single adapter
pytest tests/adapters/test_mytool_adapter.py -v

## Test all adapters (v0.9.0: 112/113 tests passing)
pytest tests/adapters/ -v

## Run with coverage (CI requires ≥85%)
pytest tests/adapters/ --cov=scripts.core.adapters --cov-report=term-missing

```

**Reference Implementations:**

- **Simple pattern:** [trivy_adapter.py](scripts/core/adapters/trivy_adapter.py) — Direct Finding creation, multiple finding types
- **Complex pattern:** [trufflehog_adapter.py](scripts/core/adapters/trufflehog_adapter.py) — NDJSON handling, helper functions

**Performance Impact:**

- **Plugin loading:** ~10ms overhead per adapter (negligible)
- **Auto-discovery:** ~50ms total for 12 adapters (negligible)
- **Hot-reload:** Instant (no cache clearing needed)

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

**Implementation Pattern (v0.9.0 Refactoring):**

All scan targets follow a consistent pattern using `ScanOrchestrator`:

```python
# 1. Target Collection (via collectors)
from scripts.cli.target_collectors import ImageCollector
images = ImageCollector.collect_images(args)

# 2. Scanner Execution (via scanner classes)
from scripts.cli.scan_jobs.image_scanner import ImageScanner
scanner = ImageScanner(scan_config)
results = scanner.scan_targets(images)

# 3. Results Storage
# - Write to results/individual-images/<image>/{tool}.json
# - Store in SQLite history database (v1.0.0)

```

**Key Architectural Decisions:**

- **v0.9.0 Refactoring:** Extracted `ScanOrchestrator` for unified orchestration
- **Scanner classes:** 6 target-specific scanners (Repository, Image, IaC, URL, GitLab, K8s)
- **Parallel execution:** All target types use ThreadPoolExecutor for concurrent scanning
- **Consistent logging:** Each scan target type has distinct log prefix (`repo`, `image`, `IaC`, `URL`, `GitLab`, `K8s`)
- **Directory isolation:** Each target type writes to separate `individual-{type}/` directories
- **Error resilience:** `--allow-missing-tools` writes empty stubs, allowing partial results
- **Unified reporting:** `normalize_and_report.py` scans all 6 directories and deduplicates across targets

**Tool Assignments by Target Type (v0.6.2):**

| Target Type      | Primary Tools       | Secondary Tools                                                      |
|------------------|---------------------|----------------------------------------------------------------------|
| Repositories     | trufflehog, semgrep | trivy, noseyparker, bandit, syft, checkov, hadolint, falco, afl++    |
| Container Images | trivy, syft         | -                                                                    |
| IaC Files        | checkov, trivy      | -                                                                    |
| Web URLs         | zap, nuclei             | -                                                                    |
| GitLab Repos     | Full repository scanner | trufflehog, semgrep, bandit, trivy, syft, checkov, hadolint, noseyparker, falco, afl++ |
| Kubernetes       | trivy                   | -                                                                    |

**Key Changes (v0.6.2):**

- **GitLab Repos:** Now run full repository scanner (10/12 tools) instead of trufflehog-only
- **Web URLs:** Added Nuclei for fast API security scanning alongside ZAP
- **GitLab Container Discovery:** Auto-discovers and scans container images found in Dockerfiles, docker-compose.yml, K8s manifests

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

**v1.0.0 Metadata Wrapper:**

All output formats now include a metadata envelope:

```json
{
  "meta": {
    "output_version": "1.0.0",
    "jmo_version": "0.9.0",
    "schema_version": "1.2.0",
    "timestamp": "2025-11-05T12:34:56Z",
    "scan_id": "abc123...",
    "profile": "balanced",
    "tools": ["trivy", "semgrep"],
    "target_count": 5,
    "finding_count": 42,
    "platform": {"os": "linux", "python": "3.11.0"}
  },
  "findings": [...]
}

```

**Report phase writes to `<results_dir>/summaries/`:**

- `findings.json` — Unified normalized findings with v1.0.0 metadata wrapper
- `SUMMARY.md` — Human-readable summary with severity counts and top rules
- `findings.yaml` — Optional YAML format with v1.0.0 metadata wrapper
- `dashboard.html` — Self-contained interactive HTML dashboard (dual-mode for >1000 findings)
- `findings.sarif` — SARIF 2.1.0 for code scanning platforms (GitHub, GitLab, etc.)
- `findings.csv` — v1.0.0: Spreadsheet-friendly CSV export with metadata header
- `SUPPRESSIONS.md` — Summary of suppressed findings (when `jmo.suppress.yml` is present)
- `COMPLIANCE_SUMMARY.md` — Multi-framework compliance mapping
- `PCI_DSS_COMPLIANCE.md` — PCI DSS 4.0 specific report
- `attack-navigator.json` — MITRE ATT&CK Navigator layer
- `timings.json` — Profiling data (when `--profile` flag used)

**v1.0.0 Changes:**

- **Metadata wrapper:** All formats include `{"meta": {...}, "findings": [...]}`
- **CSV reporter:** New format for Excel/spreadsheet analysis
- **Dual-mode HTML:** <1000 findings = inline (fast), >1000 findings = external JSON (prevents browser freeze)
- **Performance:** 95% reduction in dashboard load time for large scans (30-60s → <2s)

### Configuration

**jmo.yml** controls tool selection, output formats, thresholds, and profiles (v0.5.0):

```yaml
default_profile: balanced
tools: [trufflehog, semgrep, syft, trivy, checkov, hadolint, zap]
outputs: [json, md, yaml, html, sarif, csv]  # v1.0.0: Added CSV
fail_on: ""  # Optional: CRITICAL/HIGH/MEDIUM/LOW/INFO
retries: 0   # Global retry count for flaky tools
threads: 4   # Default parallelism

# v0.9.0: Email notifications
email:
  enabled: false
  provider: resend  # Only provider supported
  api_key: ${RESEND_API_KEY}
  from: "security@example.com"
  to: ["team@example.com"]
  on_scan_complete: true
  on_threshold_exceeded: true

# v0.9.0: Scheduled scans
schedule:
  enabled: false
  interval: "0 2 * * *"  # Daily at 2 AM (cron format)
  profile: "balanced"

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
- **Reporter tests** (`tests/reporters/`): Verify output formats (JSON/MD/YAML/HTML/SARIF/CSV)
- **Integration tests** (`tests/integration/`): End-to-end CLI flows, profile/thread behavior, CI gating
- **v1.0.0 feature tests:**
  - `tests/unit/test_history_db.py` — SQLite storage (100% coverage)
  - `tests/unit/test_diff_engine.py` — Diff engine (96% coverage)
  - `tests/unit/test_trend_analyzer.py` — Trend analysis (100% coverage)
  - `tests/unit/test_developer_attribution.py` — Developer tracking (100% coverage)
  - `tests/reporters/test_diff_*_reporter.py` — Diff output formats (100% coverage)
  - `tests/reporters/test_csv_reporter.py` — CSV export (100% coverage)

**Test Patterns:**

- Use `tmp_path` fixture for isolated file operations
- Fabricate minimal tool JSONs to test adapters
- Mock subprocess calls when testing tool invocation logic
- Assert on specific exit codes for `--fail-on` thresholds
- **v1.0.0:** Mock `time.time()` for timing-dependent tests (trend analysis)

**Coverage:**

CI enforces ≥85% coverage (see [.github/workflows/ci.yml](.github/workflows/ci.yml)). Upload to Codecov uses OIDC (tokenless) for public repos.

## CI/CD

**GitHub Actions Workflows:**

The project uses 5 workflows for full CI/CD automation:

1. **[.github/workflows/ci.yml](.github/workflows/ci.yml)** — Primary CI workflow
   - `quick-checks` job: actionlint, yamllint, deps-compile freshness, guardrails, badge verification (2-3 min)
   - `test-matrix` job: Ubuntu/macOS × Python 3.10/3.11/3.12 (parallel, independent)
   - `lint-full` job: Full pre-commit suite (nightly scheduled runs only)
   - Triggers: push, pull_request, workflow_dispatch, schedule (nightly at 6 AM UTC)

2. **[.github/workflows/release.yml](.github/workflows/release.yml)** — Release automation
   - `pre-release-check` job: Blocks release if tools outdated (CRITICAL GATE)
   - `pypi-publish` job: Build and publish to PyPI (Trusted Publishers OIDC)
   - `docker-build` job: Multi-arch Docker images (full/balanced/slim/fast variants)
   - `docker-scan` job: Trivy vulnerability scanning
   - `verify-badges` job: Verify PyPI badges after publish
   - Triggers: version tags (`v*`), workflow_dispatch

3. **[.github/workflows/weekly-tool-update.yml](.github/workflows/weekly-tool-update.yml)** — Weekly automation (NEW)
   - Runs every Sunday at 00:00 UTC
   - Updates ALL security tools to latest versions via `update_versions.py --update-all`
   - Syncs Dockerfiles automatically
   - Creates PR with auto-merge enabled
   - Merges automatically if CI passes
   - Triggers: schedule (weekly), workflow_dispatch

4. **[.github/workflows/automated-release.yml](.github/workflows/automated-release.yml)** — One-click releases (NEW)
   - Manual trigger with version bump type (patch/minor/major) and changelog entry
   - Updates ALL tools before release
   - Bumps version in pyproject.toml
   - Updates CHANGELOG.md
   - Creates release PR
   - Triggers: workflow_dispatch only

5. **[.github/workflows/version-check.yml](.github/workflows/version-check.yml)** — Version consistency (EXISTING)
   - Runs weekly to detect outdated tools
   - Fails CI if CRITICAL tools outdated
   - Sends alerts for non-critical updates
   - Triggers: schedule (weekly Sunday 02:00 UTC), workflow_dispatch

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

**v1.0.0 CI/CD Integration Examples:**

**GitHub Actions - Diff on PR:**

```yaml
- name: Scan baseline (main branch)
  run: jmo scan --repo . --results-dir results-baseline

- name: Scan current (PR branch)
  run: jmo scan --repo . --results-dir results-current

- name: Generate diff
  run: jmo diff results-baseline/ results-current/ --format md > diff.md

- name: Post diff as PR comment
  uses: actions/github-script@v6
  with:
    script: |
      const fs = require('fs');
      const diff = fs.readFileSync('diff.md', 'utf8');
      github.rest.issues.createComment({
        issue_number: context.issue.number,
        owner: context.repo.owner,
        repo: context.repo.repo,
        body: diff
      });

```

**GitLab CI - Trend Analysis with Cache:**

```yaml
security-scan:
  script:
    - jmo scan --repo . --profile-name balanced
    - jmo trends analyze --export prometheus
  cache:
    key: ${CI_PROJECT_ID}
    paths:
      - .jmo/history.db
  artifacts:
    paths:
      - results/
      - .jmo/history.db
    expire_in: 30 days

```

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
- JSON/Markdown: `basic_reporter.py` (v1.0.0 metadata wrapper)
- YAML: `yaml_reporter.py` (v1.0.0 metadata wrapper)
- HTML: `html_reporter.py` (v1.0.0 dual-mode: inline vs external)
- SARIF: `sarif_reporter.py` (maps to SARIF 2.1.0 schema)
- CSV: `csv_reporter.py` (v1.0.0: spreadsheet export)
- **v1.0.0:** All reporters must include metadata wrapper
- Update `scripts/cli/jmo.py:cmd_report()` to call new reporter
- Add tests in `tests/reporters/`

### Changing CLI Behavior

- Main CLI: `scripts/cli/jmo.py`
- Subcommands: `scan`, `report`, `ci`, `diff`, `history`, `trends`, `schedule`, `adapters`, `wizard`, `setup`
- **v0.9.0 refactoring:** Orchestrators extracted to separate files:
  - `scan_orchestrator.py` — Scan orchestration
  - `report_orchestrator.py` — Report orchestration
  - `ci_orchestrator.py` — CI orchestration
- **v1.0.0 new commands:**
  - `diff_commands.py` — Diff CLI
  - `history_commands.py` — Historical storage CLI
  - `trend_commands.py` — Trend analysis CLI
- When modifying flags/behavior:
  1. Update `parse_args()` function in `jmo.py`
  2. Update `README.md`, `QUICKSTART.md`, `SAMPLE_OUTPUTS.md`
  3. Add/update tests in `tests/cli/` and `tests/integration/`

### Updating Dependencies

- **Runtime deps:** Declared in `pyproject.toml` under `[project.dependencies]`
  - `PyYAML>=6.0` (required for jmo.yml)
  - `croniter>=1.0` (v0.9.0: schedule management)
  - `requests>=2.31.0` (v0.9.0: EPSS/KEV integration)
  - `scipy>=1.11.0` (v1.0.0: Mann-Kendall statistical test)
- **Optional deps:** `[project.optional-dependencies]` for reporters (jsonschema), email (resend), MCP (mcp[cli])
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

| Task                     | Skill to Use              | Trigger                                        |
|--------------------------|---------------------------|------------------------------------------------|
| Adding new tool adapter  | jmo-adapter-generator     | "Add support for [tool]"                       |
| Writing adapter tests    | jmo-test-fabricator       | "Write tests for [tool] adapter"               |
| Debugging CI failures    | jmo-ci-debugger           | "CI is failing", "GitHub Actions not working"  |
| Updating documentation           | jmo-documentation-updater | "Update docs for [feature]"              |
| Optimizing scan performance      | jmo-profile-optimizer     | "Scans are too slow", "Too many timeouts" |
| Adding new target type           | jmo-target-type-expander  | "Scan [AWS/npm/GraphQL/etc.]"            |
| Mapping to compliance frameworks | jmo-compliance-mapper     | "What frameworks does [CWE] map to?"     |
| Preparing for release            | dev-helper                | "Bump version to X.Y.Z"                  |

**Skills are guides, not rigid requirements.** If project constraints require a different approach, document the deviation in your PR description or code comments. Consider updating the skill if the deviation becomes a common pattern.

## Skill Auto-Activation

Claude Code automatically activates skills based on natural language patterns. You don't need to remember skill names - just describe what you want to do.

### Common Trigger Patterns

| User Request                 | Auto-Activated Skill      | Example                              |
|------------------------------|---------------------------|--------------------------------------|
| "Add support for [tool]"     | jmo-adapter-generator     | "Add support for Snyk"               |
| "Scans are too slow"         | jmo-profile-optimizer     | "Optimize balanced profile"          |
| "CI is failing"              | jmo-ci-debugger           | "GitHub Actions timeout"             |
| "Write tests for [adapter]"  | jmo-test-fabricator       | "Write tests for snyk_adapter.py"    |
| "Map [CWE] to frameworks"    | jmo-compliance-mapper     | "Map CWE-79 to OWASP"                |
| "Fix [vulnerability]"        | jmo-security-hardening    | "Fix CSRF in API"                    |
| "Refactor [function]"        | jmo-refactoring-assistant | "Refactor cmd_scan"                  |
| "Document [feature]"         | jmo-documentation-updater | "Document AWS scanning"              |
| "[tool] not working"         | jmo-systematic-debugging  | "Semgrep returns no findings"        |
| "Build React [component]"    | jmo-dashboard-builder     | "Add SBOM tree view"                 |

### How It Works

1. **User describes task** in natural language
2. **Claude matches pattern** to appropriate skill
3. **Skill activates automatically** with context
4. **Workflow begins** without manual skill invocation

### Override Auto-Activation

If you want to use a specific skill explicitly:

```text
"Use the jmo-profile-optimizer skill to analyze timings.json"

```

This ensures the exact skill is used, even if the pattern might match multiple skills.

### Full Trigger Patterns

See [dev-only/hybrid-implementation-files/02-natural-language-triggers.md](dev-only/hybrid-implementation-files/02-natural-language-triggers.md) for complete trigger pattern reference.

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

## Parallel Multi-Skill Workflows

For independent tasks, use Task tool parallelism to achieve 2-3x speedup.

### Workflow Example: Add New Tool (Parallel)

**Sequential (Old):** 6-8 hours

```text
1. jmo-adapter-generator (2-3 hours)
2. jmo-test-fabricator (1-2 hours)
3. jmo-documentation-updater (30-45 min)

```

**Parallel (New):** 3-4 hours (2x speedup)

```text
Launch 3 agents in parallel:
- Agent 1: jmo-adapter-generator (code)
- Agent 2: jmo-test-fabricator (tests)
- Agent 3: jmo-documentation-updater (docs)

Wait for all to complete → integrate results

```

### When to Use Parallel

✅ **Use parallel when:**

- Tasks are independent (no data dependencies)
- Each task takes >30 minutes
- Total time savings >50%

❌ **Don't use parallel when:**

- Tasks depend on each other (adapter must exist before tests)
- Tasks are quick (<5 minutes)
- Coordination overhead > time savings

### Parallel Workflow Patterns

#### Pattern 1: Fan-out/Fan-in (Independent Analysis)

```text
User: "Analyze performance and dependencies before refactoring"
  ↓
Fork:
  - Agent 1: jmo-profile-optimizer (analyze timings.json)
  - Agent 2: dependency-analyzer (analyze dependencies)
  ↓
Join: Combine results
  ↓
jmo-refactoring-assistant (refactor with full context)

```

#### Pattern 2: Pipeline (Sequential with Parallel Stages)

```text
User: "Add AWS scanning and document it"
  ↓
Stage 1: jmo-target-type-expander (sequential)
  ↓
Stage 2 (parallel):
  - Agent 1: jmo-test-fabricator (write tests)
  - Agent 2: jmo-documentation-updater (document feature)
  ↓
Integration: Merge results

```

**Full Parallel Workflows:** See [dev-only/hybrid-implementation-files/13-parallel-workflows.md](dev-only/hybrid-implementation-files/13-parallel-workflows.md)

### Skill Maintenance

Skills use **Semantic Versioning** and are updated on a regular schedule:

- **Weekly:** jmo-ci-debugger (GitHub Actions API changes)
- **Monthly:** jmo-documentation-updater (documentation structure adjustments)
- **Quarterly:** jmo-compliance-mapper (MITRE ATT&CK updates)
- **Annually:** jmo-compliance-mapper (CWE Top 25, OWASP Top 10, NIST CSF, CIS Controls)
- **As Needed:** All others (when core architecture changes)

See [.claude/skills/INDEX.md#skill-maintenance](.claude/skills/INDEX.md#skill-maintenance) for complete versioning and update process.

## Agents vs. Skills

JMo Security uses a **hybrid architecture** combining skills (domain-specific workflows) and agents (autonomous detection/validation).

### When to Use Skills (Agents vs. Skills)

✅ **Use Skills When:**

- Known workflow exists (e.g., adding adapter, optimizing profiles)
- Step-by-step guidance needed
- Domain expertise required (security, compliance, profiling)
- Consistency matters (following JMo patterns)

**Examples:**

- "Add Snyk scanner" → jmo-adapter-generator
- "Scans too slow" → jmo-profile-optimizer
- "Fix CSRF" → jmo-security-hardening

### When to Use Agents

✅ **Use Agents When:**

- Proactive detection needed (find issues before user notices)
- Automated validation required (pre-release checks)
- Impact analysis before changes (refactoring safety)
- Broad codebase scanning (not targeted fixes)

**Examples:**

- "Find coverage gaps" → coverage-gap-finder agent
- "Verify release readiness" → release-readiness agent
- "What depends on jmo.py?" → dependency-analyzer agent
- "Check if docs up-to-date" → doc-sync-checker agent

### Retained Agents (4)

| Agent | Purpose | Use Case | Integration |
|-------|---------|----------|-------------|
| **coverage-gap-finder** | Find untested code paths | Before release, weekly checks | → jmo-test-fabricator |
| **release-readiness** | Pre-release validation | Before tagging versions | → jmo-ci-debugger |
| **dependency-analyzer** | Analyze code dependencies | Before refactoring | → jmo-refactoring-assistant |
| **doc-sync-checker** | Detect documentation drift | After features, weekly | → jmo-documentation-updater |

### Retired Agents (3)

- ❌ **security-auditor** - Redundant with jmo-security-hardening skill
- ❌ **code-quality-auditor** - Redundant with jmo-refactoring-assistant skill
- ❌ **codebase-explorer** - Use faster `Explore` agent instead

### Agent Coordination Patterns

#### Pattern 1: Agent → Skill (Detection → Fix)

```text
coverage-gap-finder (detect gaps) → jmo-test-fabricator (write tests)
doc-sync-checker (detect drift) → jmo-documentation-updater (fix docs)

```

#### Pattern 2: Skill → Agent → Skill (Safe Refactoring)

```bash
User: "Refactor cmd_scan"
  → dependency-analyzer (analyze impact)
  → jmo-refactoring-assistant (refactor safely)

```

### Proactive Agent Triggers

**Weekly (Automated):**

- Sunday 10 PM UTC: coverage-gap-finder, doc-sync-checker

**Pre-Release (Automated):**

- Before `git tag`: release-readiness

**Post-Feature (Automated):**

- After scripts/ modified: doc-sync-checker

**Manual:**

- "Find coverage gaps" → coverage-gap-finder
- "Verify release readiness" → release-readiness
- "Analyze dependencies of [file]" → dependency-analyzer
- "Check doc sync" → doc-sync-checker

**Full Agent Policy:** See [dev-only/hybrid-implementation-files/03-agent-usage-policy.md](dev-only/hybrid-implementation-files/03-agent-usage-policy.md)

## Code-as-Memory System (.mcp-skills/)

JMo Security uses a **code-as-memory approach** where your codebase IS the memory. Instead of storing abstractions in JSON files, Claude analyzes actual implementation patterns directly from your code.

### Philosophy: Your Codebase is the Memory

**Why this approach:**

- ✅ **Always up-to-date** - Code is the source of truth, not stale summaries
- ✅ **Zero maintenance** - No manual memory updates needed
- ✅ **Higher fidelity** - Actual patterns > summarized memories
- ✅ **Natural workflow** - Already how you develop (copy-modify existing adapters)
- ✅ **98.7% context reduction** - Load only what's needed via MCP

**Traditional memory problems solved:**

- ❌ Old memory system: 4 files created in 2 weeks (unused)
- ❌ Manual updates: Forgot to store patterns after implementation
- ❌ Stale data: Patterns outdated after refactoring
- ✅ **New approach:** Always accurate, zero effort

### MCP Skills Directory

```bash
.mcp-skills/
├── README.md                       # Skills overview
├── adapter-pattern-analyzer.py     # Extract patterns from existing adapters
├── test-pattern-matcher.py         # Find test structures to reuse
├── quick-coverage.py               # Fast coverage check without full suite
└── (add more skills as needed)

```

### How It Works

**1. Pattern Analysis (Automatic)**

```bash
## When you ask: "Add Snyk scanner"
## Claude automatically runs:
python3 .mcp-skills/adapter-pattern-analyzer.py trivy

## Output: Real patterns from actual code
{
  "parse_method": {"parameters": "output_path: Path", "return_type": "list[Finding]"},
  "finding_creation": ["schemaVersion=\"1.2.0\", id=\"\", ruleId=..."],
  "error_handling": ["try-except blocks", "file existence check"],
  "imports": ["from scripts.core.common_finding import (", ...]
}

## Claude uses ACTUAL trivy_adapter.py patterns to create snyk_adapter.py

```

**2. Test Pattern Reuse**

```bash
## Claude runs:
python3 .mcp-skills/test-pattern-matcher.py trivy

## Output: Real test structure
{
  "test_count": 12,
  "fixtures": ["tmp_path", "JSON fixtures: trivy-vuln.json"],
  "mock_patterns": ["@patch: Path.exists", "@patch: json.load"],
  "coverage_estimate": "85%+ (comprehensive)"
}

## Uses actual test_trivy_adapter.py as template

```

**3. Quick Validation**

```bash
## Fast coverage check after writing new adapter
python3 .mcp-skills/quick-coverage.py scripts/core/adapters/snyk_adapter.py

## Output:
{
  "coverage": "87.5%",
  "files_analyzed": 1
}

```

### Example Workflow

```bash
You: "Add Snyk scanner"

Claude:
  1. python3 .mcp-skills/adapter-pattern-analyzer.py trivy
     → Extracts: plugin decorator, Finding creation, error handling
  2. Reads scripts/core/adapters/trivy_adapter.py directly
  3. Creates scripts/core/adapters/snyk_adapter.py with ACTUAL patterns
  4. python3 .mcp-skills/test-pattern-matcher.py trivy
     → Extracts: fixtures, mocks, assertions
  5. Reads tests/adapters/test_trivy_adapter.py directly
  6. Creates tests/adapters/test_snyk_adapter.py with ACTUAL test structure
  7. python3 .mcp-skills/quick-coverage.py scripts/core/adapters/snyk_adapter.py
     → Validates: 85%+ coverage achieved

Result: 40-60% time savings, 100% accurate patterns

```

### Benefits Over JSON Memory

| Aspect | Old JSON Memory | New Code-as-Memory |
|--------|----------------|-------------------|
| **Accuracy** | Summaries (stale) | Source code (always current) |
| **Maintenance** | Manual edits | Zero (auto-analysis) |
| **Usage Rate** | 0% (unused) | 95%+ (natural workflow) |
| **Time Savings** | 0% (never used) | 40-60% (proven) |
| **Context Overhead** | Medium | Ultra-low (98.7% reduction) |
| **Fidelity** | Abstractions | Actual implementations |

### Adding New Skills

Create Python scripts in `.mcp-skills/` that analyze your codebase:

```python
#!/usr/bin/env python3
"""
Example: Compliance Pattern Finder

Finds how existing code maps CWEs to compliance frameworks.
"""
import json
from pathlib import Path

def find_compliance_mappings(cwe_id: str):
    # Read actual compliance_mapper.py code
    mapper_code = Path("scripts/core/compliance_mapper.py").read_text()

    # Extract real mappings (not summaries)
    # ... analysis logic ...

    return {"cwe": cwe_id, "frameworks": [...]}

if __name__ == "__main__":
    # Use from command line or Claude calls it automatically
    pass

```

### Privacy & Security

- Skills are **gitignored** in `.mcp-skills/` (optional - can commit if useful)
- No secrets or PII stored
- Reads only your local codebase
- Safe to delete (just helper scripts)

**Note:** The `.jmo/` directory still exists for local workspace (scan history via `.jmo/history.db`), but memory system removed.

## Pre/Post-Operation Hooks

JMo Security uses hooks to automate quality enforcement at key points in the development workflow.

### Recommended Hooks Configuration

Add to `.claude/hooks.json`:

```json
{
  "pre-edit": {
    "command": "make lint-file {file}",
    "description": "Lint file before editing"
  },
  "post-edit": {
    "command": "make fmt-file {file}",
    "description": "Format file after editing"
  },
  "pre-task": {
    "command": "make verify-env",
    "description": "Verify environment before starting task"
  },
  "post-task": {
    "command": "pytest --cov={changed_files} --cov-fail-under=85",
    "description": "Run tests on changed files after task"
  },
  "pre-release": {
    "command": "claude-code agent release-readiness",
    "description": "Run release-readiness agent before tagging"
  }
}

```

### Hook Execution Flow

```bash
User: "Add Snyk adapter"
  ↓
pre-task hook: make verify-env
  ↓
jmo-adapter-generator skill
  ↓
pre-edit hook: make lint-file scripts/core/adapters/snyk_adapter.py
  ↓
Edit file
  ↓
post-edit hook: make fmt-file scripts/core/adapters/snyk_adapter.py
  ↓
post-task hook: pytest --cov=scripts/core/adapters/snyk_adapter.py
  ↓
Done (with automated quality checks)

```

### Benefits

- **Enforce quality automatically** - No manual `make` commands
- **Catch issues early** - Pre-edit linting prevents broken code
- **Maintain consistency** - Post-edit formatting ensures style
- **Verify coverage** - Post-task testing ensures ≥85%

### When to Disable Hooks Temporarily

```bash
## For rapid prototyping (skip formatting)
export SKIP_HOOKS=post-edit

## For large refactors (skip tests until done)
export SKIP_HOOKS=post-task

## Re-enable
unset SKIP_HOOKS

```

**Full Hooks Guide:** See [dev-only/hybrid-implementation-files/10-hooks-configuration.md](dev-only/hybrid-implementation-files/10-hooks-configuration.md)

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

### Results Directory Layout (v1.0.0)

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
    ├── findings.json          # v1.0.0: Unified findings with metadata wrapper
    ├── SUMMARY.md             # Summary with severity counts
    ├── findings.yaml          # v1.0.0: YAML format with metadata wrapper
    ├── dashboard.html         # v1.0.0: Interactive dashboard (dual-mode)
    ├── findings.sarif         # SARIF 2.1.0 format
    ├── findings.csv           # v1.0.0: CSV export for spreadsheets
    ├── SUPPRESSIONS.md        # Suppression summary
    ├── COMPLIANCE_SUMMARY.md  # v0.5.1: Multi-framework compliance
    ├── PCI_DSS_COMPLIANCE.md  # v0.5.1: PCI DSS report
    ├── attack-navigator.json  # v0.5.1: MITRE ATT&CK Navigator
    └── timings.json           # Performance profiling (when --profile used)

```

**Important:** Never change default paths without updating all tests and documentation.

**v1.0.0 Note:** `normalize_and_report.py` automatically scans all 6 target directories. Findings are deduplicated across all target types by fingerprint ID. All outputs include v1.0.0 metadata wrapper.

### SQLite Database Layout (v1.0.0)

```bash
.jmo/
└── history.db              # SQLite database
    ├── schema_version      # Migration tracking
    ├── scans               # Scan metadata (commit, profile, tools, counts)
    ├── findings            # Individual findings (fingerprint-based)
    └── trends              # Pre-computed trend statistics

```

**Critical Docker Requirement:**

```bash
## MUST mount .jmo/history.db for persistence
docker run --rm \
  -v $PWD/.jmo:/scan/.jmo \
  -v $PWD:/scan \
  -v $PWD/results:/results \
  jmo-security:latest scan --repo /scan

```

## Release Process

**Two Release Methods:**

### Method 1: Automated Release (Recommended)

Use the automated-release workflow for one-click releases:

```bash
## Navigate to GitHub Actions → Automated Release → Run workflow
## Select:
##   - Version bump: patch/minor/major
##   - Changelog entry: "Brief summary of changes"

```

**What it does automatically:**

1. Updates ALL security tools to latest versions
2. Bumps version in pyproject.toml
3. Updates CHANGELOG.md with your entry
4. Creates release PR with detailed summary
5. When PR merged → automatically creates tag and triggers full release workflow

**Advantages:**

- ✅ Zero manual steps
- ✅ Guaranteed tool updates before release
- ✅ Consistent commit messages and PR structure
- ✅ Cannot accidentally skip tool updates

### Method 2: Manual Release (Advanced)

For advanced users who want full control:

**CRITICAL: All security tools MUST be updated before EVERY release.**

1. **Update ALL security tools to latest versions:**

   ```bash
   python3 scripts/dev/update_versions.py --check-latest  # Check for updates
   python3 scripts/dev/update_versions.py --update-all    # Update all tools
   python3 scripts/dev/update_versions.py --sync          # Sync Dockerfiles
   git add versions.yaml Dockerfile*
   git commit -m "deps(tools): update all to latest before vX.Y.Z"
   ```

2. Bump version in `pyproject.toml` under `[project] version`
3. Update `CHANGELOG.md` with changes
4. Commit with message: `release: vX.Y.Z`
5. Create and push tag: `git tag vX.Y.Z && git push --tags`
6. **CI enforces tool updates** — Release BLOCKS if tools outdated (pre-release-check job)
7. CI publishes to PyPI automatically using Trusted Publishers (OIDC)
8. CI verifies badges auto-update correctly (60s after PyPI publish)

**Prerequisites:**

- Configure repo as Trusted Publisher in PyPI settings (one-time setup)
- No `PYPI_API_TOKEN` required with OIDC workflow
- **CRITICAL:** All tools must be up-to-date (enforced by CI pre-release gate)

**Badge Automation:**

- All README badges auto-update from PyPI (no manual edits needed)

**Weekly Tool Updates:**

The project uses automated weekly tool updates to ensure all security tools stay current:

- **Schedule:** Every Sunday at 00:00 UTC
- **Process:**
  1. `weekly-tool-update.yml` workflow runs automatically
  2. Updates ALL tools to latest versions via `update_versions.py --update-all`
  3. Syncs Dockerfiles automatically
  4. Creates PR with auto-merge enabled
  5. Merges automatically if CI tests pass
- **Benefits:**
  - Zero manual intervention for tool updates
  - Continuous security improvements
  - Early detection of breaking changes (fails CI if incompatible)
  - PRs provide clear audit trail of what changed
- **Override:** Can manually trigger via GitHub Actions → Weekly Tool Update → Run workflow
- Badge verification runs on every release (`.github/workflows/release.yml`)
- Badge CDN caching: expect 5-30 minute delay for global propagation
- Manual verification: `make verify-badges`
- See [docs/BADGE_AUTOMATION.md](docs/BADGE_AUTOMATION.md) for complete guide

## Troubleshooting

### Tests Failing

- Run `make test` locally with `--maxfail=1` to stop at first failure
- Check coverage with `pytest --cov --cov-report=term-missing`
- Ensure `requirements-dev.txt` is up to date: `make deps-compile`
- **v1.0.0:** Check for timing-dependent tests (trend analysis, diff engine)

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

### SQLite Database Issues (v1.0.0)

- **Database locked:** Close other connections, use `jmo history vacuum`
- **Corrupted database:** Run `jmo history verify` to check integrity
- **Permission denied:** Ensure `.jmo/` directory is writable
- **Docker persistence:** Verify volume mount `-v $PWD/.jmo:/scan/.jmo`

### Diff/Trend Analysis Issues (v1.0.0)

- **No historical data:** Ensure scans stored in SQLite (`jmo history list`)
- **Diff shows no changes:** Verify fingerprint stability (check `common_finding.py`)
- **Trend analysis fails:** Check Python 3.10+ (scipy requirement)
- **Statistical test fails:** Need ≥7 data points for Mann-Kendall test

## Additional Resources

- **Claude Skills Index: [.claude/skills/INDEX.md](.claude/skills/INDEX.md)** — Complete skill catalog with workflows
- User Guide: [docs/USER_GUIDE.md](docs/USER_GUIDE.md)
- **Docker Variants: [docs/DOCKER_VARIANTS_MASTER.md](docs/DOCKER_VARIANTS_MASTER.md)** — Complete tool distribution across 4 variants (full, balanced, slim, fast)
- Quick Start: [QUICKSTART.md](QUICKSTART.md)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)
- Testing: [TEST.md](TEST.md)
- Release Process: [docs/RELEASE.md](docs/RELEASE.md)
- **Version Management: [docs/VERSION_MANAGEMENT.md](docs/VERSION_MANAGEMENT.md)** (v0.6.1+)
- **v1.0.0 Feature Plans:**
  - SQLite Storage: [dev-only/1.0.0/archive/SQLITE_STORAGE_COMPLETE_PLAN.md](dev-only/1.0.0/archive/SQLITE_STORAGE_COMPLETE_PLAN.md)
  - Machine-Readable Diffs: [dev-only/1.0.0/archive/DESIGN_MACHINE_READABLE_DIFFS.md](dev-only/1.0.0/archive/DESIGN_MACHINE_READABLE_DIFFS.md)
  - Trend Analysis: [dev-only/1.0.0/archive/TREND_ANALYSIS_COMPLETE_PLAN.md](dev-only/1.0.0/archive/TREND_ANALYSIS_COMPLETE_PLAN.md)
  - Output Formats: [dev-only/1.0.0/archive/OUTPUT_FORMAT_REVIEW_COMPLETE_PLAN.md](dev-only/1.0.0/archive/OUTPUT_FORMAT_REVIEW_COMPLETE_PLAN.md)
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
## Store drafts and analysis in gitignored locations
echo "analysis notes" > .claude/draft-analysis.md
echo "temp script" > dev-only/test-script.sh
echo "results" > /tmp/scan-output.json

## These files NEVER appear in git status
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
## After creating or modifying documentation
## The skill will:
## 1. Check for duplicates and consolidate
## 2. Verify against Perfect Documentation Structure
## 3. Update docs/index.md with new links
## 4. Run markdownlint and fix ALL issues
## 5. Organize into appropriate locations
## 6. Archive or delete obsolete docs

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
    ├── WIZARD_IMPLEMENTATION.md       # Wizard implementation details (for contributors)
    ├── RELEASE.md                     # Release process for maintainers
    ├── MCP_SETUP.md                   # MCP server setup instructions
    ├── examples/
    │   ├── README.md                  # Examples index
    │   ├── wizard-examples.md         # Wizard workflows and patterns
    │   ├── diff-workflows.md          # v1.0.0: Diff usage examples
    │   ├── ci-cd-trends.md            # v1.0.0: Trend analysis CI/CD
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
   - Start: [docs/DOCKER_README.md#quick-start-absolute-beginners](docs/DOCKER_README.md#quick-start-absolute-beginners) OR run `jmo wizard`
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
- **v1.0.0:** Added sections for diff, history, trend analysis

**docs/DOCKER_README.md:**

- Purpose: Complete Docker guide for all skill levels
- Content: Image variants, CI/CD patterns, troubleshooting, security considerations
- Length: Medium-long
- Updates: When new Docker images, variants, or CI examples added
- **v1.0.0:** Added volume mounting requirements for `.jmo/history.db`

**docs/examples/wizard-examples.md:**

- Purpose: Wizard workflows and use cases
- Content: Interactive mode, non-interactive mode, artifact generation, common patterns
- Length: Medium
- Updates: When wizard features or flags added
- **v1.0.0:** Added post-scan trend analysis prompts

**docs/examples/diff-workflows.md (v1.0.0):**

- Purpose: Machine-readable diff usage examples
- Content: PR review workflows, regression detection, CI/CD integration
- Length: Medium
- Updates: When diff features or formats added

**docs/examples/ci-cd-trends.md (v1.0.0):**

- Purpose: Trend analysis CI/CD integration
- Content: GitHub Actions, GitLab CI, cache strategies, artifact persistence
- Length: Medium
- Updates: When trend commands or export formats added

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

1. **New Major Feature** (SQLite storage, Diff, Trend Analysis)
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

## YAML Configuration Files (Root Directory)

JMo Security uses 10 YAML/YML files in the root directory, organized by purpose:

### **JMo-Specific Configuration (3 files)**

| File | Purpose | Moveable? |
|------|---------|-----------|
| `jmo.yml` | Main JMo configuration: tool selection, profiles, thresholds, email, scheduling | ❌ NO - Hardcoded in 50+ tests/scripts |
| `jmo.suppress.yml` | Suppression rules for false positives (by fingerprint, ruleId, path) | ❌ NO - Scanned during report phase |
| `versions.yaml` | Central tool version registry (v0.6.1+) for all security tools | ❌ NO - Referenced by CI and update_versions.py |

### **Tooling Configuration (4 files)**

| File | Purpose | Moveable? |
|------|---------|-----------|
| `.pre-commit-config.yaml` | Pre-commit hook configuration (formatting, linting, validation) | ❌ NO - MUST be in root per pre-commit spec |
| `.yamllint.yaml` | Yamllint rules (line length, indentation) | ❌ NO - MUST be in root for yamllint to find it |
| `bandit.yaml` | Bandit security scanner configuration (excludes, skipped tests) | ❌ NO - MUST be in root for bandit to find it |
| `docker-compose.yml` | Docker Compose examples for running JMo scans | ⚠️ OPTIONAL - Standard convention is root |

### **CI/CD & Documentation (3 files)**

| File | Purpose | Moveable? |
|------|---------|-----------|
| `codecov.yml` | Codecov coverage reporting configuration | ⚠️ OPTIONAL - Root is conventional but could use `.github/codecov.yml` |
| `.readthedocs.yaml` | Read the Docs documentation build configuration | ❌ NO - MUST be in root per RTD spec |
| `mkdocs.yml` | MkDocs documentation site configuration | ⚠️ OPTIONAL - Standard convention is root |

### **Organization Rationale**

**Why NOT move to `config/` directory:**

1. **Industry conventions:** Most tools expect configs in root (pre-commit, Docker, RTD, yamllint, bandit)
2. **Breaking changes:** Moving `jmo.yml` or `versions.yaml` would break 50+ test files and CI workflows
3. **Low clutter:** 10 config files is reasonable for mature projects (Django has 15+, Linux kernel has 20+)
4. **Clear naming:** `.` prefix = tooling config (hidden), `jmo.` prefix = JMo-specific
5. **Time vs ROI:** 2-4 hours to reorganize with near-zero functional benefit and high breakage risk

**Modification Guidelines:**

- **jmo.yml:** Edit directly for tool/profile changes (see [Configuration](#configuration) section)
- **versions.yaml:** Use `update_versions.py` script, NEVER manual edits (see [Version Management](#version-management-v061))
- **jmo.suppress.yml:** Add suppressions during report phase when identifying false positives
- **Tooling configs:** Edit when adding new hooks, linting rules, or CI integrations

## Docker Image Variants (Root Directory)

JMo Security provides **4 Docker image variants** optimized for different use cases:

| Dockerfile | Purpose | Size | Tools | Use Case |
|------------|---------|------|-------|----------|
| `Dockerfile` | Full variant - All 28 security tools | ~1.97 GB | 26 Docker-ready (28 total, 2 manual) | Security audits, compliance, pre-release validation |
| `Dockerfile.balanced` | Production-ready comprehensive coverage | ~1.41 GB | 21 scanners | CI/CD pipelines, regular audits, production scans |
| `Dockerfile.slim` | Cloud/Kubernetes focused | ~557 MB | 15 cloud-focused tools | Cloud CSPM, Kubernetes security, serverless |
| `Dockerfile.fast` | CI/CD gate optimized | ~502 MB | 8 fastest scanners | Pre-commit checks, PR validation, quick scans |

### Variant Selection Guide

**Use `Dockerfile` (full) when:**

- Running comprehensive security audits
- Compliance scans requiring maximum coverage
- Pre-release validation needing exhaustive checks
- Time is not critical (30-60 min scans acceptable)

**Use `Dockerfile.balanced` (default) when:**

- Running regular CI/CD pipeline scans
- Balancing coverage and speed (15-20 min scans)
- Production deployment security checks
- Need DAST (ZAP) + core SAST/SCA

**Use `Dockerfile.slim` when:**

- Scanning cloud infrastructure (AWS/Azure/GCP)
- Kubernetes cluster security auditing
- Need Prowler + Kubescape + Trivy
- Optimizing for smaller image size

**Use `Dockerfile.fast` when:**

- Pre-commit hooks (5-8 min scans)
- Pull request validation gates
- Developer local scans
- CI/CD resource constraints (GitHub Actions free tier)

### Organization Rationale

**Why NOT move to `docker/` directory:**

1. **Docker conventions:** Docker CLI expects `Dockerfile` in project root by default
2. **Variant naming standard:** `Dockerfile.<variant>` is industry convention (Prometheus, GitLab, Kubernetes)
3. **CI/CD tight coupling:** 5+ workflows reference `Dockerfile.${{ matrix.variant }}`
4. **Build simplicity:** `docker build -f Dockerfile.balanced .` is simpler than `docker build -f docker/Dockerfile.balanced .`
5. **Time vs ROI:** 2-3 hours to reorganize with high breakage risk, near-zero functional benefit

### Modification Guidelines

**CRITICAL: Use version management automation for tool updates:**

```bash
# Update tool versions (NEVER edit Dockerfiles manually)
python3 scripts/dev/update_versions.py --tool trivy --version 0.58.0
python3 scripts/dev/update_versions.py --sync  # Sync all Dockerfiles

# Verify consistency
python3 scripts/dev/update_versions.py --sync --dry-run
```

**See:**

- Complete variant guide: [docs/DOCKER_VARIANTS_MASTER.md](docs/DOCKER_VARIANTS_MASTER.md)
- Version management: [docs/VERSION_MANAGEMENT.md](docs/VERSION_MANAGEMENT.md)
- Tool distribution matrix: [docs/DOCKER_VARIANTS_MASTER.md#tool-distribution-matrix](docs/DOCKER_VARIANTS_MASTER.md#tool-distribution-matrix)

## Key Files Reference

| File | Purpose |
|------|---------|
| `scripts/cli/jmo.py` | Main CLI entry point (scan/report/ci/diff/history/trends) |
| `scripts/cli/wizard.py` | Interactive wizard implementation |
| `scripts/cli/diff_commands.py` | Diff command implementations (v1.0.0) |
| `scripts/cli/history_commands.py` | History command implementations (v1.0.0) |
| `scripts/cli/trend_commands.py` | Trend analysis commands (v1.0.0) |
| `scripts/cli/trend_formatters.py` | Trend output formatters (v1.0.0) |
| `scripts/core/normalize_and_report.py` | Aggregation engine, deduplication, enrichment |
| `scripts/core/config.py` | Config loader for jmo.yml |
| `scripts/core/common_finding.py` | CommonFinding schema and fingerprinting |
| `scripts/core/history_db.py` | SQLite storage for scan history (v1.0.0) |
| `scripts/core/diff_engine.py` | Diff computation engine (v1.0.0) |
| `scripts/core/trend_analyzer.py` | Statistical trend analysis (v1.0.0) |
| `scripts/core/trend_exporters.py` | Trend export formats (v1.0.0) |
| `scripts/core/developer_attribution.py` | Git blame integration (v1.0.0) |
| `scripts/core/adapters/*.py` | Tool output parsers (plugin architecture) |
| `scripts/core/reporters/*.py` | Output formatters (JSON/MD/YAML/HTML/SARIF/CSV) |
| `scripts/core/reporters/diff_json_reporter.py` | JSON diff reporter (v1.0.0) |
| `scripts/core/reporters/diff_md_reporter.py` | Markdown diff reporter (v1.0.0) |
| `scripts/core/reporters/diff_html_reporter.py` | HTML diff reporter (v1.0.0) |
| `scripts/core/reporters/diff_sarif_reporter.py` | SARIF diff reporter (v1.0.0) |
| `scripts/core/reporters/csv_reporter.py` | CSV reporter (v1.0.0) |
| `scripts/dev/update_versions.py` | **Version management automation (v0.6.1+)** |
| `jmo.yml` | Main configuration file |
| `versions.yaml` | **Central tool version registry (v0.6.1+)** |
| `pyproject.toml` | Python package metadata and build config |
| `Makefile` | Developer shortcuts for common tasks |
| `Dockerfile`, `Dockerfile.balanced`, `Dockerfile.slim`, `Dockerfile.fast` | Docker image variants (4 active: full, balanced, slim, fast) |
| `.pre-commit-config.yaml` | Pre-commit hook configuration |
| `.github/workflows/ci.yml` | Primary CI: tests, quick checks, nightly lint |
| `.github/workflows/release.yml` | Release automation: PyPI + Docker builds |
| `.github/workflows/version-check.yml` | **Weekly version consistency checks (v0.6.1+)** |
| `.github/dependabot.yml` | **Automated dependency updates (v0.6.1+)** |
| `.jmo/history.db` | **SQLite historical storage (v1.0.0)** |
| `dev-only/1.0.0/STATUS.md` | **v1.0.0 development progress tracker** |
| `dev-only/1.0.0/archive/*.md` | **Completed feature documentation** |
