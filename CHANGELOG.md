# Changelog

For the release process, see docs/RELEASE.md.

## Unreleased

## 0.4.3 (2025-10-14)

**Patch Release: CI/CD Security & Docker Hub Integration**

This release fixes critical CI/CD infrastructure issues and enables Docker Hub README synchronization:

**Bug Fixes:**

1. **Trivy SARIF upload to GitHub Security**:
   - Fixed "Resource not accessible by integration" error
   - Root cause: Missing `security-events: write` permission in workflow
   - Solution: Added `security-events: write` to release.yml permissions
   - Trivy vulnerability scans now upload successfully to GitHub Security dashboard

2. **Docker Hub README synchronization**:
   - Upgraded to `peter-evans/dockerhub-description@v4` (was v3)
   - Changed trigger to version tags only (was main branch)
   - Added repository variable gate: `vars.DOCKERHUB_ENABLED == 'true'`
   - Added helpful skip message with setup instructions when disabled
   - Ready to enable when Docker Hub credentials configured

**Documentation:**

- **CLAUDE.md**: Added comprehensive "CI/CD Common Fixes (Lessons Learned)" section
  - Docker tag extraction from metadata-action
  - Actionlint parameter updates (fail_level vs fail_on_error)
  - Docker image testing commands (--help vs --version)
  - SARIF upload permissions requirements
  - Docker Hub README sync configuration

**Technical Details:**

- release.yml: Added `security-events: write` to workflow permissions (line 19)
- release.yml: Enhanced docker-hub-readme job with proper gating and v4 action (lines 196-228)
- CLAUDE.md: Added CI/CD troubleshooting reference (lines 316-356)

No functional changes to tools, CLI, or outputs. CI/CD infrastructure improvements only.

## 0.4.2 (2025-10-14)

**Patch Release: Docker Image Test Fix**

This release fixes the Docker image testing step that was failing in v0.4.1:

**Bug Fix:**

- **Docker image tests using unsupported CLI flag**:
  - Fixed test step trying to run `jmo --version` which doesn't exist
  - Root cause: jmo CLI uses subcommands (scan/report/ci) and doesn't have a top-level `--version` flag
  - Solution: Changed tests to use `jmo --help` and `jmo scan --help` which are supported
  - All 3 Docker variants (full, slim, alpine) now pass tests successfully

**Technical Details:**
- release.yml: Updated Docker image test commands to use `--help` instead of `--version`
- No changes to Docker images themselves - they were building correctly all along

No functional changes to tools, CLI, or outputs. Purely CI/CD test infrastructure fix.

## 0.4.1 (2025-10-14)

**Patch Release: Docker Build Fixes**

This release fixes two critical CI issues discovered in v0.4.0:

**Bug Fixes:**

1. **Docker tag mismatch** causing test failures:
   - Fixed test step trying to pull `v0.4.0-full` when images were tagged as `0.4.0-full`
   - Root cause: metadata-action strips 'v' prefix, but test logic didn't account for it
   - Solution: Extract tag directly from metadata output

2. **Actionlint deprecation warning**:
   - Replaced deprecated `fail_on_error: true` with `fail_level: error`
   - Resolves VSCode diagnostic warning in ci.yml

**Technical Details:**
- release.yml: Use `steps.meta.outputs.tags` for accurate Docker image testing
- release.yml: Strip 'v' prefix in docker-scan job for tag consistency
- ci.yml: Update reviewdog/action-actionlint parameters to current API

No functional changes to tools, CLI, or outputs. Purely CI/CD infrastructure improvements.

## 0.4.0 (2025-10-14)

**Major Release: Workflow Consolidation + Wizard + Docker**

This release completes ROADMAP items #1 (Docker All-in-One Images) and #2 (Interactive Wizard), and introduces a streamlined CI/CD infrastructure to reduce maintenance burden and CI breakage.

### GitHub Actions Workflow Consolidation (NEW)

**Problem solved:** Frequent CI breakage due to 5 separate workflows with overlapping concerns, serial dependencies, and duplicate pre-commit runs.

**Changes:**

- **Consolidated 5 workflows → 2 workflows** (60% reduction):
  - New [.github/workflows/ci.yml](.github/workflows/ci.yml): Primary CI with quick-checks, test-matrix, and nightly lint-full jobs
  - Enhanced [.github/workflows/release.yml](.github/workflows/release.yml): PyPI publishing + Docker multi-arch builds
  - Deleted: tests.yml, docker-build.yml, lint-full.yml, deps-compile-check.yml

- **ci.yml jobs:**
  - `quick-checks` (2-3 min): actionlint, yamllint, deps-compile freshness, guardrails
  - `test-matrix` (6-10 min, parallel): Ubuntu/macOS × Python 3.10/3.11/3.12
    - Tests run independently (no lint blocking!)
    - Coverage + Codecov upload on Ubuntu 3.11 only
  - `lint-full` (nightly only): Full pre-commit suite at 6 AM UTC

- **release.yml jobs:**
  - `pypi-publish`: Build and publish to PyPI
  - `docker-build`: Multi-arch images (full/slim/alpine)
  - `docker-scan`: Trivy vulnerability scanning
  - `docker-hub-readme`: README sync (placeholder)

**Benefits:**
- **~40% faster CI feedback** (~6-10 min vs ~10-15 min)
- **No test blocking:** Tests run even if lint fails
- **Clearer separation:** CI (validation) vs Release (distribution)
- **Easier maintenance:** Single source of truth for CI logic
- **Nightly drift detection:** Catches pre-commit hook drift before it breaks PRs

**Nightly CI Explained:**
- Runs automatically every night at 6 AM UTC via GitHub Actions cron
- Executes full pre-commit suite in check-only mode
- Catches tool version drift, rule changes, and dependency shifts
- Does NOT run on normal pushes/PRs (keeps CI fast)
- Prevents surprise failures during development

### Interactive Wizard (ROADMAP Item 2 - October 2025)

**Guided first-run experience for beginners:**

- **Interactive wizard command** (`jmotools wizard`):
  - Step-by-step prompts for profile selection (fast/balanced/deep with time estimates)
  - Docker vs native mode selection with auto-detection
  - Target selection (repo/repos-dir/targets/TSV) with repository auto-discovery
  - Advanced configuration (threads, timeout, fail-on severity)
  - Preflight summary with generated command preview
  - Automatic execution and results opening
- **Non-interactive mode** (`--yes` flag):
  - Uses smart defaults for scripting and automation
  - Profile: balanced, Target: current directory, Docker: auto-detected
- **Docker mode integration** (`--docker` flag):
  - Leverages completed ROADMAP #1 Docker images
  - Zero-installation path for beginners
  - Detects Docker availability and running status
- **Artifact generation**:
  - `--emit-make-target`: Generate Makefile targets
  - `--emit-script`: Generate executable shell scripts
  - `--emit-gha`: Generate GitHub Actions workflows (both native and Docker variants)
- **Smart defaults**:
  - CPU-based thread recommendations
  - Profile-based timeout configurations
  - System detection (OS, Docker, repo discovery)
- **Comprehensive documentation**:
  - Wizard examples guide: [docs/examples/wizard-examples.md](docs/examples/wizard-examples.md)
  - Updated README and QUICKSTART with wizard instructions
  - 18 comprehensive tests with 100% pass rate

**Usage:**

```bash
# Interactive mode
jmotools wizard

# Non-interactive (automation)
jmotools wizard --yes

# Force Docker mode
jmotools wizard --docker

# Generate artifacts
jmotools wizard --emit-make-target Makefile.security
jmotools wizard --emit-script scan.sh
jmotools wizard --emit-gha .github/workflows/security.yml
```

**Testing:**

- 18 unit tests covering all wizard functionality
- Command generation for native and Docker modes
- Artifact generation (Makefile/shell/GHA)
- Profile validation and resource estimates
- Non-interactive mode and smart defaults

### Docker All-in-One Images (ROADMAP Item 1 - October 2025)

**Zero-installation friction for immediate scanning:**

- **3 Docker image variants** (full, slim, alpine) with all security tools pre-installed
  - **Full image** (~500MB): 11+ scanners including gitleaks, trufflehog, noseyparker, semgrep, bandit, syft, trivy, checkov, tfsec, hadolint, osv-scanner
  - **Slim image** (~200MB): 6 core scanners for fast CI/CD (gitleaks, semgrep, syft, trivy, checkov, hadolint)
  - **Alpine image** (~150MB): Minimal footprint on Alpine Linux with core tools
- **Multi-architecture support**: linux/amd64 and linux/arm64 (Apple Silicon compatible)
- **GitHub Actions workflow** (`.github/workflows/docker-build.yml`):
  - Automated build and push to GitHub Container Registry
  - Multi-platform builds with BuildKit
  - Trivy vulnerability scanning of images
  - SBOM and provenance attestations
  - SARIF upload to GitHub Security
- **Comprehensive documentation**:
  - Docker quick start guide in README with CI/CD examples
  - Full usage documentation: [docs/DOCKER_README.md](docs/DOCKER_README.md)
  - 8 GitHub Actions workflow examples: [docs/examples/github-actions-docker.yml](docs/examples/github-actions-docker.yml)
  - Docker Compose configuration for common use cases
- **Developer-friendly**:
  - Makefile targets: `docker-build`, `docker-build-all`, `docker-test`, `docker-push`
  - Optimized `.dockerignore` to minimize build context
  - Health checks and proper labels
  - Read-only volume mounts for security

**Usage:**

```bash
# Pull and scan
docker pull ghcr.io/jimmy058910/jmo-security:latest
docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results /scan/results --profile balanced

# CI/CD integration
container:
  image: ghcr.io/jimmy058910/jmo-security:latest
steps:

  - run: jmo ci --repo . --fail-on HIGH --profile
```

**Testing:**

- Integration tests: `tests/integration/test_docker_images.py`
- Validates tool availability, version checks, and basic scan functionality
- Docker Compose syntax validation

**Distribution:**

- Primary: GitHub Container Registry (`ghcr.io/jimmy058910/jmo-security`)
- Planned: Docker Hub support (configuration ready)
- Automated builds on push to main and tagged releases

### Code Quality & Security Improvements (Phase 1 - October 2025)

**Security Fixes:**

- **XSS vulnerability patched in HTML dashboard**: Added comprehensive HTML escaping function covering all dangerous characters (`&`, `<`, `>`, `"`, `'`) to prevent cross-site scripting attacks in the interactive dashboard.

**Critical Bug Fixes:**

- **OSV scanner fully integrated**:
  - Integrated `osv_adapter` into `normalize_and_report.py` aggregation pipeline
  - Added OSV scanner tool invocation to CLI scan command
  - Enabled vulnerability detection from OSV database for comprehensive open-source vulnerability scanning

**Code Quality & Maintainability:**

- **Magic numbers extracted to constants**: Extracted `FINGERPRINT_LENGTH` (16) and `MESSAGE_SNIPPET_LENGTH` (120) as named constants with documentation in `common_finding.py`
- **Severity type safety**: Converted severity strings to proper `Enum` with comparison operators (`<`, `>`, `<=`, `>=`) while maintaining full backward compatibility. Enables cleaner severity-based filtering and sorting throughout the codebase.
- **Backward compatibility for suppressions**: Updated `suppress.py` to support both `suppressions` (recommended) and `suppress` (legacy) keys in YAML config without breaking existing workflows
- **Configurable CPU count**: Moved hardcoded CPU recommendation logic to `jmo.yml` `profiling` section (min/max/default threads) for better configurability across different environments

**Enhanced Outputs:**

- **SARIF enrichment**: Enhanced SARIF 2.1.0 output with:
  - Code snippets in region context for better IDE integration
  - CWE/OWASP/CVE taxonomy references for security categorization
  - CVSS scores and metadata for vulnerability prioritization
  - Richer rule descriptions and fix suggestions
  - Better GitHub/GitLab code scanning integration

**Documentation:**

- **ROADMAP.md updates**:
  - Removed 124-line duplicate section
  - Added 9 new future enhancement steps (Steps 15-23):
    - Policy-as-Code Integration (OPA)
    - Supply Chain Attestation (SLSA)
    - Docker All-in-One Image
    - Machine-Readable Diff Reports
    - Web UI for Results Exploration
    - Plugin System for Custom Adapters
    - Scheduled Scans & Cron Support
    - GitHub App Integration
    - React/Vue Dashboard Alternative
- **Configuration updates**: Added `profiling` section to `jmo.yml` for thread recommendations with configurable min/max/default values

**Testing:**

- All 100 tests passing ✅
- Coverage: 88% (exceeds 85% requirement)
- Backward compatibility verified across all changes
- No breaking changes to existing workflows

### Developer Experience (October 2025)

Developer experience improvements:

- Optional reproducible dev deps via pip-tools and uv:
  - Added `requirements-dev.in` and Make targets: `upgrade-pip`, `deps-compile`, `deps-sync`, `deps-refresh`, `uv-sync`.
  - Local pre-commit hook auto-runs `deps-compile` when `requirements-dev.in` changes.
  - CI workflow `deps-compile-check` ensures `requirements-dev.txt` stays fresh on PRs.

No changes to runtime packaging. Existing workflows (`make dev-deps`, `make dev-setup`) continue to work unchanged.

## 0.3.0 (2025-10-12)

Highlights:

- Documentation now reflects the `jmo report <results_dir>` syntax across README, Quickstart, User Guide, and example workflows.
- Packaging adds a `reporting` extra (`pip install jmo-security[reporting]`) bundling PyYAML and jsonschema for YAML output and schema validation.
- Acceptance suite updated to exercise the current dashboard generator and wrapper scripts end-to-end.
- Shell/Python lint fixes ensure `make lint` runs cleanly in CI and locally.

Operational notes:

- Acceptance fixtures expanded to cover additional TruffleHog output shapes while cleaning up temp artifacts automatically.
- Repository metadata bumped to 0.3.0 (`pyproject.toml`, roadmap) to align with this release.

## 0.2.0

Highlights:

- HTML reporter enhancements: sortable columns, tool filter dropdown, CSV/JSON export, persisted filters/sort, deep-links, and theme toggle.
- Profiling mode (`--profile`) now records per-job timings and thread recommendations. Timing metadata exposed.
- Thread control improvements: `--threads` flag with precedence over env/config; config supports `threads:`.
- New adapters: Syft (SBOM), Hadolint (Dockerfiles), Checkov and tfsec (IaC). Aggregator wired to load their outputs when present.
- Devcontainer now installs gitleaks, trufflehog, and semgrep for turnkey use.
- Packaging scaffold via `pyproject.toml` with `jmo` console script.
- Profiles and per-tool overrides in config (tools/threads/timeout/include/exclude; per_tool flags/timeout)
- Retries for flaky tool invocations with success-code awareness per tool
- Graceful cancel in scan (SIGINT/SIGTERM)
- Optional human-friendly colored logs via `--human-logs`

Roadmap items completed in this release:

- Profiles and per-tool overrides; retries; graceful cancel; human logs
- Syft→Trivy enrichment and expanded adapters (Syft, Trivy, Hadolint, Checkov, tfsec)
- HTML dashboard improvements and profiling summary
- CLI consolidation (scan/report/ci) with robust exit codes
- Local verification scripts (verify-env, populate_targets), docs and examples

Notes:

- Syft adapter emits INFO package entries and vulnerability entries when present; used for context and future cross-linking.
- Backwards compatibility maintained; features are additive.

Planned (future ideas):

- Additional adapters and policy scanners
- Richer cross-tool correlation and dedupe
- Configurable SARIF tuning and rule metadata enrichment
- Optional containerized all-in-one image for turnkey runs

## 0.1.0

- Initial CLI and adapters (Gitleaks, TruffleHog, Semgrep, Nosey Parker, OSV, Trivy)
- Unified reporters (JSON, Markdown, YAML, HTML, SARIF) and suppression report
- Config file, aggregation, and basic performance optimizations

---

## Roadmap Summary (Steps 1–13)

- Step 1 — Repo hygiene & DX: Pre-commit, Black/Ruff/Bandit/ShellCheck/shfmt/markdownlint; Makefile targets; strict shell conventions.
- Step 2 — Local verification: `ci-local.sh`, `install_tools.sh`, and `make verify` for terminal-first validation without remote CI.
- Step 3 — CommonFinding schema: v1.0.0 schema established for normalized finding outputs.
- Step 4 — Adapters: Secrets (gitleaks, trufflehog, noseyparker), SAST (semgrep, bandit), SBOM/vuln (syft, trivy), IaC (checkov, tfsec), Dockerfile (hadolint), OSV.
- Step 5 — Config-driven runs: profiles, per-tool overrides, include/exclude, threads, timeouts, retries, log levels; CLI precedence wired.
- Step 6 — Reporters & outputs: JSON/MD/YAML/HTML/SARIF; suppression report; profiling metadata (timings.json) consumed by HTML.
- Step 7 — CLI consolidation: `jmo scan|report|ci` with clear exit codes; human logs option; robust help.
- Step 8 — Reliability & DX polish: retries with tool-specific success codes, graceful cancel, per-tool timeouts, concurrency, Syft→Trivy enrichment.
- Step 9 — Testing: Unit, integration, snapshot tests across adapters/reporters/CLI; coverage gate (~85%).
- Step 10 — Supply chain & optional CI: SBOM (Syft), Trivy scan, optional SARIF-ready outputs for code scanning; remote CI optional.
- Step 11 — Tooling expansion: additional adapters and normalization; severity harmonization and dedupe.
- Step 12 — Distribution & dev envs: packaging via `pyproject.toml`, devcontainer, curated tools in dev env.
- Step 13 — Docs & examples: polished README/QUICKSTART/USER_GUIDE; examples and screenshots; suppression docs.

Notes

- These steps are broadly complete; ongoing incremental polish may land across releases.
